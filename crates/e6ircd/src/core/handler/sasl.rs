//! SASL authentication (PLAIN, OAUTHBEARER).

use super::*;

// ---- SASL ---------------------------------------------------------------

pub(super) fn sasl_fail(state: &mut ServerState, conn: ConnId) {
    state.sessions.get_mut(&conn).expect("checked").sasl = crate::core::state::SaslState::Idle;
    state.numeric(conn, ERR_SASLFAIL, &[], Some("SASL authentication failed"));
}

/// A credential verification was denied — either a definitive rejection
/// (`unavailable == false`) or a store fault (`unavailable == true`). Routed by
/// the verdict's own `origin` so a SASL denial fails the SASL attempt and a
/// NickServ IDENTIFY denial answers NickServ, never the reverse. The session
/// flag is consulted only for liveness: a denial for an attempt already aborted
/// or superseded is dropped rather than answered twice.
fn verify_denied(
    state: &mut ServerState,
    conn: ConnId,
    origin: crate::core::CredentialOrigin,
    unavailable: bool,
) {
    match origin {
        crate::core::CredentialOrigin::Sasl => {
            if state.sessions[&conn].sasl == crate::core::state::SaslState::Verifying {
                sasl_fail(state, conn);
            }
            // else: stale reply for an aborted SASL attempt — drop it.
        }
        crate::core::CredentialOrigin::NickServIdentify => {
            let Some(label) = state
                .sessions
                .get_mut(&conn)
                .expect("checked")
                .pending_identify
                .take()
            else {
                return; // stale IDENTIFY reply (superseded/aborted)
            };
            let text = if unavailable {
                "Services are temporarily unavailable. Try again later.".to_string()
            } else {
                let nick = state.sessions[&conn]
                    .nick()
                    .map(String::from)
                    .unwrap_or_else(|| "*".to_string());
                format!("Invalid password for \x02{nick}\x02.")
            };
            // Frame the failure under the IDENTIFY's label; unheld, like the
            // success path.
            state.emit_labeled_unheld(conn, label, move |state| {
                state.service_notice(conn, "NickServ", &text);
            });
        }
    }
}

/// Max credential-verification attempts per connection before the socket is
/// closed — a single connection can't drive unbounded argon2 work.
pub(super) const MAX_CREDENTIAL_ATTEMPTS_PER_CONN: u32 = 8;

/// Charge one credential-verification attempt against the connection's budget
/// before an (expensive) argon2 verify is dispatched. Returns false — and closes
/// the connection — once the budget is exceeded, bounding the online
/// brute-force / CPU-exhaustion surface even when per-IP rate limits are off.
///
/// This budget is shared across *every* command that can drive an argon2 op —
/// SASL AUTHENTICATE, NickServ IDENTIFY, and NickServ REGISTER — so no single
/// path can be looped to bypass the cap the others enforce.
pub(super) fn credential_attempt_ok(state: &mut ServerState, conn: ConnId) -> bool {
    let attempts = {
        let s = state.sessions.get_mut(&conn).expect("checked");
        s.credential_attempts += 1;
        s.credential_attempts
    };
    if attempts > MAX_CREDENTIAL_ATTEMPTS_PER_CONN {
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

/// Upper bound on a reassembled SASL response (across 400-byte continuation
/// chunks). Generous for a bearer JWT, but bounds client-driven buffering.
pub(super) const SASL_MAX: usize = 8192;

pub(super) fn cmd_authenticate(state: &mut ServerState, conn: ConnId, p: &[&str]) {
    use crate::core::state::SaslState;
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
    if arg.len() > 400 {
        state
            .sessions
            .get_mut(&conn)
            .expect("checked")
            .sasl_buf
            .clear();
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
            // chunk) completes the payload. SASL_MAX bounds the buffer so a
            // client cannot grow it without end.
            let piece = if arg == "+" { "" } else { arg };
            let over = {
                let session = state.sessions.get_mut(&conn).expect("checked");
                if session.sasl_buf.len() + piece.len() > SASL_MAX {
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
                state
                    .sessions
                    .get_mut(&conn)
                    .expect("checked")
                    .sasl_buf
                    .clear();
                sasl_fail(state, conn);
                return;
            }
            if arg.len() == 400 {
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
                // payload: base64(authzid \0 authcid \0 password)
                let parsed = e6irc_proto::base64::decode(&payload).and_then(|raw| {
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
                if !credential_attempt_ok(state, conn) {
                    return;
                }
                state.sessions.get_mut(&conn).expect("checked").sasl = SaslState::Verifying;
                let request = crate::core::DbRequest::VerifyPassword {
                    conn,
                    account,
                    password,
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
                let Some(token) = token else {
                    sasl_fail(state, conn);
                    return;
                };
                if !credential_attempt_ok(state, conn) {
                    return;
                }
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
                ERR_SASLALREADY,
                &[],
                Some("SASL authentication in progress"),
            );
        }
    }
}

pub(crate) fn db_reply(state: &mut ServerState, conn: ConnId, reply: crate::core::DbReply) {
    use crate::core::state::SaslState;
    // Session-scoped replies are moot once the client is gone — but replies
    // that carry *global* state (the hot founder map, channel access) must be
    // applied regardless: the DB has already committed, and skipping the
    // hot-map update would let it diverge from storage until restart. Worst
    // case is a FLAGS revocation whose requester disconnected mid-round-trip:
    // the DB says revoked while the hot map keeps auto-opping the revoked
    // account. The notices inside those arms degrade safely on a dead conn.
    if !state.sessions.contains_key(&conn)
        && !matches!(
            reply,
            crate::core::DbReply::ChannelRegistered { .. }
                | crate::core::DbReply::FounderChanged { .. }
                | crate::core::DbReply::ChannelAccessSet { .. }
                | crate::core::DbReply::ReadMarkerStored { .. }
                | crate::core::DbReply::ReadMarkerUnavailable { .. }
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
        } | crate::core::DbReply::Unavailable {
            origin: crate::core::CredentialOrigin::Sasl,
        }
    ) && let Some(s) = state.sessions.get_mut(&conn)
    {
        s.sasl_verify_pending = false;
    }
    match reply {
        // The verdict routes on the origin the *request* carried, never on the
        // session flags: `sasl == Verifying` and `pending_identify` can both be
        // set at once (interleaved AUTHENTICATE + NickServ IDENTIFY), and the
        // old flag-inference could fire an IDENTIFY success off a SASL reply, or
        // vice versa. The flag now only says whether that path is still live.
        crate::core::DbReply::PasswordVerified {
            account,
            origin: crate::core::CredentialOrigin::Sasl,
        } => {
            if state.sessions[&conn].sasl != SaslState::Verifying {
                return; // stale SASL reply (the attempt was aborted)
            }
            {
                let session = state.sessions.get_mut(&conn).expect("checked");
                session.sasl = SaslState::Idle;
                session.account = Some(account.clone());
            }
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
            let Some(label) = state
                .sessions
                .get_mut(&conn)
                .expect("checked")
                .pending_identify
                .take()
            else {
                return; // stale IDENTIFY reply (superseded/aborted)
            };
            state.sessions.get_mut(&conn).expect("checked").account = Some(account.clone());
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
            verify_denied(state, conn, origin, false);
        }
        crate::core::DbReply::Unavailable { origin } => {
            verify_denied(state, conn, origin, true);
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
                    let label = state
                        .sessions
                        .get_mut(&conn)
                        .expect("checked")
                        .pending_register
                        .take()
                        .flatten();
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
        crate::core::DbReply::ChannelRegisterUnavailable => {
            // ChanServ REGISTER whose persist failed — previously a bare
            // Unavailable that fell through every arm and left the founder
            // waiting forever with no response.
            state.service_notice(
                conn,
                "ChanServ",
                "Services are temporarily unavailable. Try again later.",
            );
        }
        crate::core::DbReply::AccountCreated { account, origin } => {
            state.sessions.get_mut(&conn).expect("checked").account = Some(account.clone());
            match origin {
                crate::core::AccountOrigin::NickServ => state.service_notice(
                    conn,
                    "NickServ",
                    &format!("\x02{account}\x02 is now registered to your connection."),
                ),
                crate::core::AccountOrigin::RegisterCommand => {
                    let label = state
                        .sessions
                        .get_mut(&conn)
                        .expect("checked")
                        .pending_register
                        .take()
                        .flatten();
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
                    let label = state
                        .sessions
                        .get_mut(&conn)
                        .expect("checked")
                        .pending_register
                        .take()
                        .flatten();
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
        crate::core::DbReply::ChannelRegistered {
            channel,
            founder_account,
        } => {
            // Record ownership in the hot copy so the founder is re-opped on
            // future joins without waiting for a restart. Seed it from the
            // account the DB row was actually written with (echoed on the
            // reply), not the live session — a LOGOUT/IDENTIFY between the
            // request and this reply would otherwise record the wrong founder
            // (or none), diverging the hot map from storage until restart.
            state.set_founder(&channel, &founder_account);
            // If the channel already carried a topic at registration time,
            // persist it now (KEEPTOPIC defaults on). The TOPIC command path
            // persists only on *change*, so without this the topic the founder
            // registered with is silently lost on the first empty→recreate
            // cycle — breaking the retention KEEPTOPIC promises.
            let key = state.chan_key(&channel);
            if state.keeptopic(&key)
                && let Some(topic) = state.channels.get(&key).and_then(|c| c.topic.clone())
            {
                state.registered_topics.insert(key.clone(), topic.clone());
                let request = crate::core::DbRequest::SetChannelTopic {
                    channel: key.as_str().to_string(),
                    topic: Some((topic.text, topic.set_by, topic.set_at_secs)),
                };
                if state.db_tx.try_push(request).is_err() {
                    eprintln!(
                        "chanserv: db queue full; registered topic for {} not persisted",
                        key.as_str()
                    );
                }
            }
            state.service_notice(
                conn,
                "ChanServ",
                &format!("\x02{channel}\x02 is now registered to your account."),
            );
        }
        crate::core::DbReply::ChannelExists => {
            state.service_notice(conn, "ChanServ", "That channel is already registered.");
        }
        crate::core::DbReply::FounderChanged { channel, account } => {
            // Update the hot ownership map so the new founder is re-opped.
            state.set_founder(&channel, &account);
            state.service_notice(
                conn,
                "ChanServ",
                &format!("Founder of \x02{channel}\x02 transferred to \x02{account}\x02."),
            );
        }
        crate::core::DbReply::FounderChangeFailed { channel } => {
            state.service_notice(
                conn,
                "ChanServ",
                &format!("Could not transfer \x02{channel}\x02 — no such account."),
            );
        }
        crate::core::DbReply::FounderChangeUnavailable { channel } => {
            // A store fault, not a definitive "no such account" — say so, so the
            // founder doesn't act on a false negative (e.g. re-creating an
            // account they were told doesn't exist).
            state.service_notice(
                conn,
                "ChanServ",
                &format!(
                    "Could not transfer \x02{channel}\x02 — services are temporarily unavailable."
                ),
            );
        }
        crate::core::DbReply::ChannelAccessSet {
            channel,
            account,
            flags,
            applied,
        } => {
            if !applied {
                // A grant whose account isn't registered wrote nothing; leave the
                // hot map untouched so no phantom access lingers.
                state.service_notice(
                    conn,
                    "ChanServ",
                    &format!(
                        "\x02{account}\x02 is not registered; no flags set on \x02{channel}\x02."
                    ),
                );
                return;
            }
            let key = state.chan_key(&channel);
            let account_key = state.account_key(&account);
            match &flags {
                Some(f) => {
                    // A DROP between the write and this reply unregisters the
                    // channel and cascade-deletes its access rows synchronously
                    // (`registered_founders`/`channel_access` cleared). Re-inserting
                    // here would leave a phantom hot entry for a channel the DB no
                    // longer has — and if that name is later re-registered by
                    // anyone, the phantom silently auto-ops this account, a grant
                    // the new founder never made. Skip the insert and say so.
                    if !state.is_registered(&key) {
                        state.service_notice(
                            conn,
                            "ChanServ",
                            &format!(
                                "\x02{channel}\x02 is no longer registered; the flags change \
                                 did not take effect."
                            ),
                        );
                        return;
                    }
                    state
                        .channel_access
                        .entry(key)
                        .or_default()
                        .insert(account_key, f.clone());
                    state.service_notice(
                        conn,
                        "ChanServ",
                        &format!("Flags for \x02{account}\x02 on \x02{channel}\x02 are now +{f}."),
                    );
                }
                None => {
                    if let Some(entry) = state.channel_access.get_mut(&key) {
                        entry.remove(&account_key);
                    }
                    state.service_notice(
                        conn,
                        "ChanServ",
                        &format!("Cleared flags for \x02{account}\x02 on \x02{channel}\x02."),
                    );
                }
            }
        }
        crate::core::DbReply::ChannelAccessUnavailable { channel } => {
            // A store fault, not a definitive "no such account" — say so, so
            // the operator doesn't act on a false negative (e.g. telling the
            // user to register an account that already exists).
            state.service_notice(
                conn,
                "ChanServ",
                &format!(
                    "Could not change flags on \x02{channel}\x02 — services are temporarily unavailable."
                ),
            );
        }
        crate::core::DbReply::ChannelAccessLimitReached { channel } => {
            state.service_notice(
                conn,
                "ChanServ",
                &format!(
                    "The access list for \x02{channel}\x02 is full; revoke an entry before adding another."
                ),
            );
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
            read_marker_unavailable(state, conn, account, target, display, label);
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
