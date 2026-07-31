//! Operator commands: OPER, KILL, server bans and WALLOPS.

use super::*;

// ---- OPER ---------------------------------------------------------------

pub(super) fn cmd_oper(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    let (Some(&name), Some(&password)) = (p.first(), p.get(1)) else {
        state.err_needmoreparams(conn, "OPER");
        return;
    };
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
        state.numeric(conn, ERR_PASSWDMISMATCH, &[], Some("Password incorrect"));
        return;
    }
    state.sessions.get_mut(&conn).expect("registered").oper = true;
    let nick = state.sessions[&conn]
        .nick()
        .map(String::from)
        .expect("registered");
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
fn require_oper(state: &mut ServerState, conn: ConnId) -> bool {
    if state.sessions[&conn].oper {
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

// ---- KILL ---------------------------------------------------------------

pub(super) fn cmd_kill(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    if !require_oper(state, conn) {
        return;
    }
    let Some(&target) = p.first() else {
        state.err_needmoreparams(conn, "KILL");
        return;
    };
    let key = state.nick_key(target);
    if !state.nicks.contains_key(&key) {
        state.err_nosuchnick(conn, target);
        return;
    }
    let comment = p.get(1).copied().unwrap_or("Killed");
    let oper_nick = state.sessions[&conn]
        .nick()
        .map(String::from)
        .expect("registered");
    kill_by_nick(state, target, comment, &oper_nick);
}

/// Disconnect the session currently holding `target` (by nick): audit it, snotice
/// the other opers, send the standard KILL close `ERROR`, and close it. Returns
/// whether a session was found and closed. `killer` is the display name
/// attributed in the reason and audit — an oper's nick, or an admin account for
/// the HTTP console. Shared by oper KILL and the admin console.
pub(crate) fn kill_by_nick(
    state: &mut ServerState,
    target: &str,
    comment: &str,
    killer: &str,
) -> bool {
    let key = state.nick_key(target);
    let Some(&victim) = state.nicks.get(&key) else {
        return false;
    };
    kill_connection(state, victim, comment, killer)
}

/// Disconnect one exact registered connection. HTTP control-plane rows carry
/// this immutable id, so a delayed form or API request cannot follow a released
/// nick onto a different client. IRC KILL resolves its nick once and then uses
/// this same close/audit path.
pub(crate) fn kill_connection(
    state: &mut ServerState,
    victim: ConnId,
    comment: &str,
    killer: &str,
) -> bool {
    let Some(target) = state
        .sessions
        .get(&victim)
        .filter(|session| session.is_registered())
        .and_then(|session| session.nick())
        .map(str::to_owned)
    else {
        return false;
    };
    let reason = format!("Killed ({killer} ({comment}))");
    let server = state.config.server_name.clone();
    // Audit before the close: a self-kill removes the actor's own session, and
    // recording afterwards would resolve the actor to an empty string — an
    // unattributed row in the log whose whole purpose is attribution.
    record_audit_by(state, killer, "KILL", &target, comment);
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
    let head = format!("ERROR :Closing Link: {server} (");
    let fitted = fit_trailing(&format!("{head})"), &reason);
    state.send(victim, &format!("{head}{fitted})"));
    state.close(victim, &reason);
    true
}

/// Record a privileged oper action in the audit log (best-effort; only
/// when a database is configured to hold it).
pub(super) fn record_audit(
    state: &mut ServerState,
    conn: ConnId,
    action: &str,
    target: &str,
    detail: &str,
) {
    let actor = state
        .sessions
        .get(&conn)
        .and_then(|s| s.nick().map(String::from))
        .unwrap_or_default();
    record_audit_by(state, &actor, action, target, detail);
}

/// Record an audit-log row for an actor named directly (rather than resolved
/// from a connection) — used by the HTTP admin console, which has no IRC
/// session. Same fire-and-forget persistence as [`record_audit`].
pub(crate) fn record_audit_by(
    state: &mut ServerState,
    actor: &str,
    action: &str,
    target: &str,
    detail: &str,
) {
    if !state.config.sasl_enabled {
        return;
    }
    let request = crate::core::DbRequest::AuditLog {
        actor: actor.to_string(),
        action: action.to_string(),
        target: target.to_string(),
        detail: detail.to_string(),
    };
    if state.db_tx.try_push(request).is_err() {
        eprintln!("audit: db queue full or closed; {action} action not recorded");
    }
}

/// Broadcast an operator server-notice (snotice) to every registered operator,
/// optionally skipping one connection (`except`) — used to spare a KILL victim
/// who is about to be closed. This is the minimal snotice surface: there is no
/// `+s` server-notice mask yet, so every operator sees every privileged-action
/// notice rather than subscribing to flags. Best-effort, like any NOTICE.
pub(super) fn notify_opers(state: &mut ServerState, except: Option<ConnId>, text: &str) {
    let server = state.config.server_name.clone();
    let recipients: Vec<(ConnId, String)> = state
        .sessions
        .iter()
        .filter(|(c, s)| s.is_registered() && s.oper && Some(**c) != except)
        .filter_map(|(&c, s)| s.nick().map(|n| (c, n.to_string())))
        .collect();
    for (c, nick) in recipients {
        // `text` can embed client-controlled, unbounded data (a KILL comment, a
        // ban reason), so fit it to the wire limit per recipient — the head's
        // length varies with the recipient's nick — or a maximal comment pushes
        // the line past 512 and the recipient's framing discards it whole.
        let head = format!(":{server} NOTICE {nick} :*** Notice -- ");
        let fitted = fit_trailing(&head, text);
        state.send(c, &format!("{head}{fitted}"));
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
    let server = state.config.server_name.clone();
    let nick = state.sessions[&conn]
        .nick()
        .map(String::from)
        .expect("registered");
    if p.is_empty() {
        // List current bans of this kind.
        let lines: Vec<String> = state
            .server_bans
            .iter()
            .filter(|b| b.kind == kind)
            .map(|b| {
                format!(
                    ":{server} NOTICE {nick} :{label} {} (by {}) :{}",
                    b.mask.as_str(),
                    b.set_by,
                    b.reason
                )
            })
            .collect();
        for line in lines {
            state.send(conn, &line);
        }
        state.send(
            conn,
            &format!(":{server} NOTICE {nick} :End of {label} list."),
        );
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
    // Parse the params into a guaranteed-well-formed target: the reason/mask
    // split (XLINE-aware, keyed on the trailing marker), the `*@host`
    // normalization, and the match-everyone refusal all happen inside
    // `BanMask::parse`, so nothing below can see a mis-split fragment or a
    // netban mask. A rejection is reported loudly, never silently narrowed.
    let (parsed_mask, reason) = match BanMask::parse(kind, p, has_trailing) {
        Ok(parsed) => parsed,
        Err(BanReject::MatchesEveryone(attempted)) => {
            state.send(
                conn,
                &format!(
                    ":{server} NOTICE {nick} :Refusing {label} for {attempted}: it matches every \
                     user (use a more specific mask)"
                ),
            );
            return;
        }
    };
    // A MaskKey folds for comparison (so a differently-cased UN*LINE removes it)
    // while keeping the operator's casing for STATS and the confirmation — the
    // same discipline the channel ban lists use.
    let mask = crate::core::state::MaskKey::new(parsed_mask.as_str(), casemap);
    if !state.config.sasl_enabled {
        state.send(
            conn,
            &format!(
                ":{server} NOTICE {nick} :Added {label} for {}",
                mask.as_str()
            ),
        );
        notify_opers(
            state,
            None,
            &format!("{nick} added {label} for {} ({reason})", mask.as_str()),
        );
        apply_server_ban_hot(state, mask, kind, &reason, &nick, label);
        return;
    }
    let mutation = crate::core::ServerBanMutation::add(&mask, kind, reason, nick);
    begin_oper_server_ban(state, conn, label, &mask, mutation);
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
        conn,
        label: response_label,
    };
    match queue_server_ban_mutation(state, mutation, requester) {
        Ok(()) => state.defer_captured_reply(conn),
        Err(error) => {
            let server = state.config.server_name.clone();
            let nick = state.sessions[&conn].nick().unwrap_or("*");
            let message = match error {
                QueueServerBanError::AlreadyPending => format!(
                    "A {label} change for {} is already in progress",
                    mask.as_str()
                ),
                QueueServerBanError::PersistenceUnavailable => format!(
                    "Services are temporarily unavailable; {label} not {unavailable_action}"
                ),
            };
            state.send(conn, &format!(":{server} NOTICE {nick} :{message}"));
        }
    }
}

/// Apply a database-confirmed server ban to live state and disconnect matches.
pub(crate) fn apply_server_ban_hot(
    state: &mut ServerState,
    mask: crate::core::state::MaskKey,
    kind: BanKind,
    reason: &str,
    set_by: &str,
    label: &str,
) -> usize {
    let casemap = state.casemap;
    // Replace any existing ban of this kind on the same mask (folded equality).
    state
        .server_bans
        .retain(|b| !(b.kind == kind && b.mask == mask));
    state.server_bans.push(ServerBan {
        mask: mask.clone(),
        reason: reason.to_string(),
        set_by: set_by.to_string(),
        kind,
    });
    // Disconnect any matching registered sessions (possibly including the setter
    // when driven by an oper).
    let victims: Vec<ConnId> = state
        .sessions
        .iter()
        .filter(|(_, s)| s.is_registered())
        .filter_map(|(&c, s)| {
            let subject = ServerState::ban_subject(
                kind,
                s.user().unwrap_or("*"),
                &s.host,
                s.realname().unwrap_or(""),
            );
            e6irc_proto::mask::matches(casemap, mask.as_str(), &subject).then_some(c)
        })
        .collect();
    let disconnected = victims.len();
    for victim in victims {
        state.send(
            victim,
            &format!("ERROR :Closing Link: ({label}d: {reason})"),
        );
        state.close(victim, &format!("{label}d: {reason}"));
    }
    disconnected
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

fn acknowledge_server_ban_oper(
    state: &mut ServerState,
    conn: ConnId,
    response_label: Option<String>,
    action: &str,
    kind_label: &str,
    mask: &crate::core::state::MaskKey,
) {
    if !state.sessions.contains_key(&conn) {
        return;
    }
    let server = state.config.server_name.clone();
    let nick = state.sessions[&conn].nick().unwrap_or("*").to_string();
    state.emit_deferred_labeled(conn, response_label, |state| {
        state.send(
            conn,
            &format!(
                ":{server} NOTICE {nick} :{action} {kind_label} for {}",
                mask.as_str()
            ),
        );
    });
}

pub(crate) fn server_ban_result(
    state: &mut ServerState,
    mutation: crate::core::ServerBanMutation,
    requester: crate::core::ServerBanRequester,
    result: crate::core::ServerBanResult,
) {
    let (kind_token, folded_mask) = mutation.key();
    state
        .pending_server_bans
        .remove(&(kind_token.to_string(), folded_mask.to_string()));
    let Some(kind) = BanKind::from_token(kind_token) else {
        eprintln!("core: database echoed invalid server-ban kind {kind_token:?}");
        finish_server_ban_unavailable(state, requester, "server-ban result was invalid");
        return;
    };
    if result == crate::core::ServerBanResult::Unavailable {
        finish_server_ban_unavailable(state, requester, "services are temporarily unavailable");
        return;
    }

    match mutation {
        crate::core::ServerBanMutation::Add {
            mask_display,
            reason,
            set_by,
            ..
        } => {
            let mask = crate::core::state::MaskKey::new(&mask_display, state.casemap);
            let label = kind.label();
            match requester {
                crate::core::ServerBanRequester::Oper {
                    conn,
                    label: response_label,
                } => {
                    acknowledge_server_ban_oper(state, conn, response_label, "Added", label, &mask);
                    notify_opers(
                        state,
                        None,
                        &format!("{set_by} added {label} for {} ({reason})", mask.as_str()),
                    );
                    apply_server_ban_hot(state, mask, kind, &reason, &set_by, label);
                }
                crate::core::ServerBanRequester::Admin { request_id, actor } => {
                    let disconnected =
                        apply_server_ban_hot(state, mask.clone(), kind, &reason, &actor, label);
                    notify_opers(
                        state,
                        None,
                        &format!(
                            "{actor} (console) added {label} for {} ({reason})",
                            mask.as_str()
                        ),
                    );
                    finish_admin_server_ban(
                        state,
                        request_id,
                        crate::core::AdminReply::Ok(format!(
                            "Added {label} for {} — {disconnected} session(s) disconnected",
                            mask.as_str()
                        )),
                    );
                }
            }
        }
        crate::core::ServerBanMutation::Remove {
            mask_display,
            actor,
            ..
        } => {
            let mask = crate::core::state::MaskKey::new(&mask_display, state.casemap);
            remove_server_ban_hot(state, &mask, kind);
            let label = kind.label();
            match requester {
                crate::core::ServerBanRequester::Oper {
                    conn,
                    label: response_label,
                } => {
                    acknowledge_server_ban_oper(
                        state,
                        conn,
                        response_label,
                        "Removed",
                        label,
                        &mask,
                    );
                }
                crate::core::ServerBanRequester::Admin { request_id, .. } => {
                    finish_admin_server_ban(
                        state,
                        request_id,
                        crate::core::AdminReply::Ok(format!(
                            "Removed {label} for {}",
                            mask.as_str()
                        )),
                    );
                }
            }
            notify_opers(
                state,
                None,
                &format!("{actor} removed {label} for {}", mask.as_str()),
            );
        }
    }
}

fn finish_server_ban_unavailable(
    state: &mut ServerState,
    requester: crate::core::ServerBanRequester,
    reason: &str,
) {
    match requester {
        crate::core::ServerBanRequester::Oper { conn, label } => {
            if state.sessions.contains_key(&conn) {
                let server = state.config.server_name.clone();
                let nick = state.sessions[&conn].nick().unwrap_or("*").to_string();
                state.emit_deferred_labeled(conn, label, |state| {
                    state.send(
                        conn,
                        &format!(":{server} NOTICE {nick} :Server-ban change failed: {reason}"),
                    );
                });
            }
        }
        crate::core::ServerBanRequester::Admin { request_id, .. } => {
            finish_admin_server_ban(
                state,
                request_id,
                crate::core::AdminReply::Err(format!("server-ban change failed: {reason}")),
            );
        }
    }
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
        state.numeric(
            conn,
            ERR_NEEDMOREPARAMS,
            &[&format!("UN{}", kind.as_str().to_uppercase())],
            Some("Not enough parameters"),
        );
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
    let server = state.config.server_name.clone();
    let nick = state.sessions[&conn]
        .nick()
        .map(String::from)
        .expect("registered");
    let exists = state
        .server_bans
        .iter()
        .any(|ban| ban.kind == kind && ban.mask == mask);
    if !exists {
        state.send(
            conn,
            &format!(
                ":{server} NOTICE {nick} :No {label} found for {}",
                mask.as_str()
            ),
        );
        return;
    }
    if !state.config.sasl_enabled {
        remove_server_ban_hot(state, &mask, kind);
        state.send(
            conn,
            &format!(
                ":{server} NOTICE {nick} :Removed {label} for {}",
                mask.as_str()
            ),
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
    let server = state.config.server_name.clone();
    let oper_nick = state.sessions[&conn]
        .nick()
        .map(String::from)
        .expect("registered");
    // A host must be a single non-empty token without user/prefix chars.
    // A host rides in every future prefix built for this user, so an unbounded
    // one makes every subsequent line unfittable at the source — bound it here
    // (63 bytes, the DNS label/hostname norm) alongside the character rules.
    if newhost.is_empty() || newhost.len() > 63 || newhost.contains([' ', '@', '!', '\0']) {
        state.send(
            conn,
            &format!(":{server} NOTICE {oper_nick} :Invalid host: {newhost}"),
        );
        return;
    }
    let nk = state.nick_key(nick);
    let Some(target) = state.registered_peer(&nk) else {
        state.err_nosuchnick(conn, clip_echo(nick));
        return;
    };
    let (user, old_prefix) = {
        let s = &state.sessions[&target];
        (s.user().map(String::from).unwrap_or_default(), s.prefix())
    };
    state.sessions.get_mut(&target).expect("checked").host = newhost.to_string();

    // Announce with the old prefix so clients can match, to every
    // chghost-capable peer (including the target), then to extended-monitor
    // watchers of the target's nick.
    let chghost = format!(":{old_prefix} CHGHOST {user} {newhost}");
    notify_event(state, target, &chghost, |c| c.chghost, true);
    // A chghost-capable target learned of the change from the CHGHOST above; a
    // client without the cap would otherwise never be told its own host moved.
    // Fill that gap with RPL_VISIBLEHOST so every target learns its new visible
    // host — the CHGHOST is for *other* clients' view, 396 is for the target's.
    if state.sessions.get(&target).is_some_and(|s| !s.caps.chghost) {
        state.numeric(
            target,
            RPL_VISIBLEHOST,
            &[newhost],
            Some("is now your visible host"),
        );
    }
    record_audit(state, conn, "SETHOST", nick, newhost);
    state.send(
        conn,
        &format!(":{server} NOTICE {oper_nick} :Set host of {nick} to {newhost}"),
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
    let line = format!("{head}{text}");
    let recipients: Vec<ConnId> = state
        .sessions
        .iter()
        .filter(|(_, s)| s.is_registered() && s.wallops)
        .map(|(c, _)| *c)
        .collect();
    for recipient in recipients {
        state.send_timed(recipient, &line);
    }
}
