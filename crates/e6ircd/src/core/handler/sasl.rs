//! SASL authentication (PLAIN, OAUTHBEARER).

use super::*;

// ---- SASL ---------------------------------------------------------------

pub(super) fn sasl_fail(state: &mut ServerState, conn: ConnId) {
    state.sessions.get_mut(&conn).expect("checked").sasl = crate::core::state::SaslState::Idle;
    // A failed authentication is a security event, not chatter: one bounded
    // line per denial (the per-connection attempt budget caps how many a
    // single socket can produce), naming the nick and host so brute-force
    // patterns are visible in the log rather than only in client numerics.
    let (nick, host) = {
        let session = &state.sessions[&conn];
        (
            session.nick().unwrap_or("*").to_string(),
            session.host.clone(),
        )
    };
    eprintln!("ircd: SASL authentication failed for {nick} from {host}");
    state.numeric(conn, ERR_SASLFAIL, &[], Some("SASL authentication failed"));
}

fn sasl_unavailable(state: &mut ServerState, conn: ConnId) {
    state.sessions.get_mut(&conn).expect("checked").sasl = crate::core::state::SaslState::Idle;
    state.numeric(
        conn,
        ERR_SASLFAIL,
        &[],
        Some("SASL authentication temporarily unavailable"),
    );
}

/// Why a credential verification did not log the session in.
#[derive(Clone, Copy)]
enum Denial {
    /// The store answered: wrong password or no such account.
    Rejected,
    /// The account name has spent its password attempts for the window, so
    /// nothing was checked.
    Throttled(crate::db::LoginRetryAfter),
    /// The store could not answer.
    Unavailable,
}

/// SASL refused because the account name's attempt window is spent: the same
/// 904 a wrong password gets (the attempt failed and may be retried), with
/// the wait in its text.
fn sasl_throttled(state: &mut ServerState, conn: ConnId, retry_after: crate::db::LoginRetryAfter) {
    state.sessions.get_mut(&conn).expect("checked").sasl = crate::core::state::SaslState::Idle;
    let text = retry_after.explanation();
    state.numeric(conn, ERR_SASLFAIL, &[], Some(&text));
}

/// A credential verification was denied, for the [`Denial`] reason. Routed by
/// the verdict's own `origin` so a SASL denial fails the SASL attempt and a
/// NickServ IDENTIFY denial answers NickServ, never the reverse. The session
/// flag is consulted only for liveness: a denial for an attempt already aborted
/// or superseded is dropped rather than answered twice.
fn verify_denied(
    state: &mut ServerState,
    conn: ConnId,
    origin: crate::core::CredentialOrigin,
    denial: Denial,
) {
    match origin {
        crate::core::CredentialOrigin::Sasl => {
            if state.sessions[&conn].sasl == crate::core::state::SaslState::Verifying {
                match denial {
                    Denial::Rejected => sasl_fail(state, conn),
                    Denial::Throttled(retry_after) => sasl_throttled(state, conn, retry_after),
                    Denial::Unavailable => sasl_unavailable(state, conn),
                }
            }
            // else: stale reply for an aborted SASL attempt — drop it.
        }
        crate::core::CredentialOrigin::NickServIdentify => {
            let Some(label) = take_identify_label(state, conn) else {
                return; // stale IDENTIFY reply (superseded/aborted)
            };
            let text = match denial {
                Denial::Unavailable => {
                    "Services are temporarily unavailable. Try again later.".to_string()
                }
                Denial::Throttled(retry_after) => retry_after.explanation(),
                Denial::Rejected => {
                    let nick = state.sessions[&conn]
                        .nick()
                        .map(String::from)
                        .unwrap_or_else(|| "*".to_string());
                    format!("Invalid password for \x02{nick}\x02.")
                }
            };
            // Frame the failure under the IDENTIFY's label; unheld, like the
            // success path.
            state.emit_labeled_unheld(conn, label, move |state| {
                state.service_notice(conn, "NickServ", &text);
            });
        }
    }
}

/// Charge one credential-verification attempt against the connection's budget
/// before the secret is checked (an expensive argon2 verify, or OPER's compare).
/// Returns false — and closes the connection — once the budget is exceeded,
/// bounding the online brute-force / CPU-exhaustion surface even when per-IP
/// rate limits are off.
///
/// This budget is shared across *every* command that checks a secret — SASL
/// AUTHENTICATE, NickServ IDENTIFY, NickServ REGISTER, and OPER — so no single
/// path can be looped to bypass the cap the others enforce.
pub(super) fn credential_attempt_ok(state: &mut ServerState, conn: ConnId) -> bool {
    if !state
        .sessions
        .get_mut(&conn)
        .expect("checked")
        .credential_attempts
        .consume()
    {
        let server = state.config.server_name.clone();
        state.send(
            conn,
            &format!(":{server} ERROR :Closing Link: too many authentication attempts"),
        );
        state.close(conn, "Too many authentication attempts");
        return false;
    }
    true
}

/// Take the pending NickServ IDENTIFY label.
fn take_identify_label(state: &mut ServerState, conn: ConnId) -> Option<Option<String>> {
    state
        .sessions
        .get_mut(&conn)
        .expect("checked")
        .pending_identify
        .take()
        .map(crate::core::state::PendingServiceReply::into_label)
}

/// Take the pending REGISTER label.
fn take_register_label(state: &mut ServerState, conn: ConnId) -> Option<String> {
    state
        .sessions
        .get_mut(&conn)
        .expect("checked")
        .pending_register
        .take()
        .and_then(crate::core::state::PendingServiceReply::into_label)
}

/// Take a parsed SASL credential payload after charging the connection's
/// attempt budget. Shared by the PLAIN and OAUTHBEARER arms, which differ only
/// in how they parse. Malformed payloads spend a slot too: otherwise an
/// attacker can produce an unbounded stream of failure events without ever
/// reaching the supposedly per-connection limit.
fn require_cred_payload<T>(parsed: Option<T>, state: &mut ServerState, conn: ConnId) -> Option<T> {
    if !credential_attempt_ok(state, conn) {
        return None;
    }
    let parsed = match parsed {
        Some(p) => p,
        None => {
            sasl_fail(state, conn);
            return None;
        }
    };
    Some(parsed)
}

pub(super) fn cmd_authenticate(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    use crate::core::state::SaslState;
    if !state.config.sasl_enabled || !state.sessions[&conn].caps.sasl {
        sasl_fail(state, conn);
        return;
    }
    let Some(&arg) = p.first() else {
        state.err_needmoreparams(conn, "AUTHENTICATE");
        return;
    };
    if state.sessions[&conn].account().is_some() {
        state.numeric(
            conn,
            ERR_SASLALREADY,
            &[],
            Some("You have already authenticated"),
        );
        return;
    }
    if arg == "*" {
        let session = state.sessions.get_mut(&conn).expect("checked");
        session.sasl = SaslState::Idle;
        session.sasl_buf.clear();
        state.numeric(
            conn,
            ERR_SASLABORTED,
            &[],
            Some("SASL authentication aborted"),
        );
        return;
    }
    // A line longer than 400 bytes is malformed; the client must chunk the
    // base64 response at 400 bytes (SASL spec).
    if arg.len() > e6irc_proto::sasl::MAX_AUTHENTICATE_CHUNK_LEN {
        let session = state.sessions.get_mut(&conn).expect("checked");
        session.sasl = SaslState::Idle;
        session.sasl_buf.clear();
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
        mechanism @ (SaslState::PlainPending | SaslState::BearerPending) => {
            // Accumulate 400-byte continuation chunks. A full 400-byte line
            // means "more follows"; a shorter line (or "+", the empty final
            // chunk) completes the payload. The shared payload bound prevents
            // a client from growing it without end.
            let piece = if arg == "+" { "" } else { arg };
            let over = {
                let session = state.sessions.get_mut(&conn).expect("checked");
                if session.sasl_buf.len() + piece.len()
                    > e6irc_proto::sasl::MAX_AUTHENTICATE_PAYLOAD_LEN
                {
                    true
                } else {
                    session.sasl_buf.push_str(piece);
                    false
                }
            };
            if over {
                // ERR_SASLTOOLONG is specified for a single over-long
                // AUTHENTICATE line (handled above); an accumulated payload
                // that outgrows the buffer is just a failed authentication, so
                // it ends with the generic ERR_SASLFAIL and a cleared buffer.
                if !credential_attempt_ok(state, conn) {
                    return;
                }
                state
                    .sessions
                    .get_mut(&conn)
                    .expect("checked")
                    .sasl_buf
                    .clear();
                sasl_fail(state, conn);
                return;
            }
            if arg.len() == e6irc_proto::sasl::MAX_AUTHENTICATE_CHUNK_LEN {
                return; // more chunks to come
            }
            let payload =
                std::mem::take(&mut state.sessions.get_mut(&conn).expect("checked").sasl_buf);
            // Only one credential verify may be outstanding per connection: each
            // is offloaded and its reply routed by ambient flags, so two in
            // flight would cross-attribute (an IDENTIFY or a still-pending
            // *aborted* SASL verify completing a fresh AUTHENTICATE). Refuse if a
            // NickServ IDENTIFY is pending, or if a prior SASL verify hasn't been
            // answered yet — `sasl_verify_pending` survives an `AUTHENTICATE *`
            // abort (which can't un-send the DB request), so re-auth waits for
            // that stale reply to drain rather than racing it.
            if state.sessions[&conn].pending_identify.is_some()
                || state.sessions[&conn].sasl_verify_pending
            {
                sasl_fail(state, conn);
                return;
            }
            if mechanism == SaslState::PlainPending {
                let parsed = e6irc_proto::sasl::parse_plain_payload(&payload);
                let Some(credentials) = require_cred_payload(parsed, state, conn) else {
                    return;
                };
                state.sessions.get_mut(&conn).expect("checked").sasl = SaslState::Verifying;
                let request = crate::core::DbRequest::VerifyPassword {
                    conn,
                    account: credentials.account,
                    password: credentials.password,
                    origin: crate::core::CredentialOrigin::Sasl,
                };
                if state.db_tx.try_push(request).is_err() {
                    // DB worker unreachable: fail loudly, never hang. No verify
                    // was enqueued, so no `DbReply` will ever arrive to clear a
                    // pending flag — which is why the flag is set only on a
                    // successful push below, never before it.
                    sasl_fail(state, conn);
                } else {
                    // The verify is now in flight; mark it pending so a queued
                    // re-auth waits for its reply (`db_reply` clears it). Setting
                    // it only *after* the push means the flag can never outlive a
                    // request that was never sent — the state that otherwise
                    // locked the connection out of auth for good.
                    state
                        .sessions
                        .get_mut(&conn)
                        .expect("checked")
                        .sasl_verify_pending = true;
                }
            } else {
                // RFC 7628: gs2-header then \x01-separated key=value fields;
                // the credential is the `auth=Bearer <token>` field.
                let token = e6irc_proto::base64::decode(&payload).and_then(|raw| {
                    raw.split(|&b| b == 0x01).find_map(|field| {
                        std::str::from_utf8(field)
                            .ok()
                            .and_then(|s| s.strip_prefix("auth=Bearer "))
                            .filter(|t| !t.is_empty())
                            .map(str::to_string)
                    })
                });
                let Some(token) = require_cred_payload(token, state, conn) else {
                    return;
                };
                state.sessions.get_mut(&conn).expect("checked").sasl = SaslState::Verifying;
                let request = crate::core::DbRequest::VerifyToken { conn, token };
                if state.db_tx.try_push(request).is_err() {
                    // DB worker unreachable: fail loudly, never hang. The verify
                    // was never enqueued, so no reply will clear a pending flag —
                    // which is why the flag is set only on a successful push
                    // below (the same fix the PLAIN arm carries; this OAUTHBEARER
                    // arm had the set-then-maybe-fail order that stuck the flag
                    // true and locked the connection out of all auth for good).
                    sasl_fail(state, conn);
                } else {
                    state
                        .sessions
                        .get_mut(&conn)
                        .expect("checked")
                        .sasl_verify_pending = true;
                }
            }
        }
        SaslState::Verifying => {
            state.numeric(
                conn,
                ERR_SASLFAIL,
                &[],
                Some("SASL authentication in progress"),
            );
        }
    }
}

pub(crate) fn db_reply(state: &mut ServerState, conn: ConnId, reply: crate::core::DbReply) {
    use crate::core::state::SaslState;
    // Session-scoped replies are moot once the client is gone — but a reply
    // that carries *account* state (a read marker, kept per account rather
    // than per connection) must be applied regardless: the DB has already
    // committed, and skipping the hot-map update would let it diverge from
    // storage until restart. The notices inside those arms degrade safely on
    // a dead conn.
    if !state.sessions.contains_key(&conn)
        && !matches!(
            reply,
            crate::core::DbReply::ReadMarkerStored { .. }
                | crate::core::DbReply::ReadMarkerUnavailable { .. }
                | crate::core::DbReply::ReadMarkerLimitReached { .. }
        )
    {
        return; // client vanished while the DB worked; nothing to do
    }
    // Any credential-verify verdict (SASL or NickServ IDENTIFY, verified or
    // denied) may have been the last thing connect-time registration was
    // waiting on; noted here before the match consumes `reply`.
    let was_verify_reply = matches!(
        reply,
        crate::core::DbReply::PasswordVerified { .. }
            | crate::core::DbReply::PasswordRejected { .. }
            | crate::core::DbReply::PasswordThrottled { .. }
            | crate::core::DbReply::Unavailable { .. }
    );
    // A SASL verify reply (even one for an aborted attempt) clears the
    // outstanding-verify marker so a queued re-auth can proceed. Only SASL
    // sets the flag, so gate the clear on the SASL origin — a NickServ IDENTIFY
    // verdict must not touch it.
    if matches!(
        reply,
        crate::core::DbReply::PasswordVerified {
            origin: crate::core::CredentialOrigin::Sasl,
            ..
        } | crate::core::DbReply::PasswordRejected {
            origin: crate::core::CredentialOrigin::Sasl,
        } | crate::core::DbReply::PasswordThrottled {
            origin: crate::core::CredentialOrigin::Sasl,
            ..
        } | crate::core::DbReply::Unavailable {
            origin: crate::core::CredentialOrigin::Sasl,
        }
    ) && let Some(s) = state.sessions.get_mut(&conn)
    {
        s.sasl_verify_pending = false;
    }
    // Suspension and credential replies are serialized through the core. Once
    // the administrative event installs this deny gate, even a successful DB
    // verification that was already in flight is converted to a denial rather
    // than recreating an authenticated session after the disconnect sweep.
    if let crate::core::DbReply::PasswordVerified { account, origin } = &reply
        && state.is_account_suspended(account)
    {
        verify_denied(state, conn, *origin, Denial::Rejected);
        return;
    }
    match reply {
        // Route credential verdicts by request origin.
        crate::core::DbReply::PasswordVerified {
            account,
            origin: crate::core::CredentialOrigin::Sasl,
        } => {
            if state.sessions[&conn].sasl != SaslState::Verifying {
                return; // stale SASL reply (the attempt was aborted)
            }
            state.sessions.get_mut(&conn).expect("checked").sasl = SaslState::Idle;
            state.set_account(conn, account.clone());
            let session = &state.sessions[&conn];
            let nick = session
                .nick()
                .map(String::from)
                .unwrap_or_else(|| "*".into());
            let user = session
                .user()
                .map(String::from)
                .unwrap_or_else(|| "*".into());
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
            // A registered client can re-authenticate mid-session (cap-notify
            // allows `CAP REQ :sasl` after registration); account-notify peers
            // must learn of the login like any other. For connect-time SASL
            // the session isn't registered yet, and this is a no-op — the
            // login is announced by the registration burst instead.
            notify_account_change(state, conn, &account);
        }
        crate::core::DbReply::PasswordVerified {
            account,
            origin: crate::core::CredentialOrigin::NickServIdentify,
        } => {
            let Some(label) = take_identify_label(state, conn) else {
                return; // stale IDENTIFY reply (superseded/aborted)
            };
            state.set_account(conn, account.clone());
            // Frame the verdict under the IDENTIFY's label (if any) so a labeled
            // client can correlate the result; an unlabeled one just gets the
            // NOTICE. Unheld — it interleaves with other output like a real server.
            let account_for_notice = account.clone();
            state.emit_labeled_unheld(conn, label, move |state| {
                state.service_notice(
                    conn,
                    "NickServ",
                    &format!("You are now identified for \x02{account_for_notice}\x02."),
                );
            });
            notify_account_change(state, conn, &account);
        }
        crate::core::DbReply::PasswordRejected { origin } => {
            verify_denied(state, conn, origin, Denial::Rejected);
        }
        crate::core::DbReply::PasswordThrottled {
            origin,
            retry_after,
        } => {
            verify_denied(state, conn, origin, Denial::Throttled(retry_after));
        }
        crate::core::DbReply::Unavailable { origin } => {
            verify_denied(state, conn, origin, Denial::Unavailable);
        }
        crate::core::DbReply::AccountRegisterUnavailable { origin } => {
            // A registration whose persist failed. Answer the way the client
            // asked rather than dropping it silently (the old bare-Unavailable
            // path did nothing for the NickServ origin).
            match origin {
                crate::core::AccountOrigin::NickServ => state.service_notice(
                    conn,
                    "NickServ",
                    "Services are temporarily unavailable. Try again later.",
                ),
                crate::core::AccountOrigin::RegisterCommand => {
                    let label = take_register_label(state, conn);
                    let nick = state.sessions[&conn]
                        .nick()
                        .map(String::from)
                        .unwrap_or_else(|| "*".to_string());
                    state.emit_deferred_labeled(conn, label, move |state| {
                        register_fail(
                            state,
                            conn,
                            "TEMPORARILY_UNAVAILABLE",
                            &nick,
                            "Account registration is temporarily unavailable",
                        );
                    });
                }
            }
        }
        crate::core::DbReply::AccountCreated { account, origin } => {
            state.set_account(conn, account.clone());
            match origin {
                crate::core::AccountOrigin::NickServ => state.service_notice(
                    conn,
                    "NickServ",
                    &format!("\x02{account}\x02 is now registered to your connection."),
                ),
                crate::core::AccountOrigin::RegisterCommand => {
                    let label = take_register_label(state, conn);
                    let server = state.config.server_name.clone();
                    let account = account.clone();
                    state.emit_deferred_labeled(conn, label, move |state| {
                        state.send(
                            conn,
                            &format!(
                                ":{server} REGISTER SUCCESS {account} :Account registered, \
                                 you are now logged in"
                            ),
                        );
                    });
                }
            }
            notify_account_change(state, conn, &account);
        }
        crate::core::DbReply::AccountExists { origin } => {
            let nick = state.sessions[&conn]
                .nick()
                .map(String::from)
                .unwrap_or_else(|| "*".to_string());
            match origin {
                crate::core::AccountOrigin::NickServ => state.service_notice(
                    conn,
                    "NickServ",
                    &format!("\x02{nick}\x02 is already registered."),
                ),
                crate::core::AccountOrigin::RegisterCommand => {
                    let label = take_register_label(state, conn);
                    state.emit_deferred_labeled(conn, label, |state| {
                        register_fail(
                            state,
                            conn,
                            "ACCOUNT_EXISTS",
                            &nick,
                            "Account already exists",
                        );
                    });
                }
            }
        }
        crate::core::DbReply::ReadMarkerStored {
            account,
            target,
            display,
            marker_ms,
            label,
        } => {
            read_marker_stored(state, conn, account, target, display, marker_ms, label);
        }
        crate::core::DbReply::ReadMarkerUnavailable {
            account,
            target,
            display,
            label,
        } => {
            read_marker_refused(
                state,
                conn,
                ReadMarkerRefusal {
                    account,
                    target,
                    display,
                    label,
                },
                "TEMPORARILY_UNAVAILABLE",
                "Read marker could not be persisted",
            );
        }
        crate::core::DbReply::ReadMarkerLimitReached {
            account,
            target,
            display,
            label,
        } => {
            read_marker_refused(
                state,
                conn,
                ReadMarkerRefusal {
                    account,
                    target,
                    display,
                    label,
                },
                "INVALID_PARAMS",
                "Too many read markers",
            );
        }
    }
    // A connect-time SASL verify that resolved may have been the last thing
    // registration was waiting on (the client sent CAP END before the verdict).
    // Now that the pending flag is cleared and the 900/903/904 have been sent in
    // order, let registration complete — a no-op if it already did or isn't
    // ready. Only a verify reply can unblock it, so other replies skip this.
    if was_verify_reply {
        super::services::maybe_complete_registration(state, conn);
    }
}

/// account-notify: tell channel peers with the cap about a login state
/// change.
pub(super) fn notify_account_change(state: &mut ServerState, conn: ConnId, account: &str) {
    if !state.sessions.get(&conn).is_some_and(|s| s.is_registered()) {
        return; // pre-registration SASL: peers cannot exist yet
    }
    let prefix = state.sessions[&conn].prefix();
    let line = format!(":{prefix} ACCOUNT {account}");
    notify_event(
        state,
        conn,
        &line,
        crate::core::state::UserEventAudience::AccountNotify,
        false,
    );
}
