//! HTTP admin-console actions, run on the core thread via [`crate::core::Input::Admin`].
//!
//! Each action reuses the exact live-state + persistence path of the equivalent
//! IRC oper/services command (extracted into shared helpers), so a console
//! action behaves identically to its IRC counterpart — same hot-list update,
//! same disconnection of matching sessions, same audit row — rather than a
//! second, divergent implementation.

use super::oper::{
    BanMask, BanReject, QueueServerBanError, apply_server_ban_hot, ban_mask, notify_opers,
    queue_server_ban_mutation, remove_server_ban_hot,
};
use super::*;
use crate::core::state::{BanKind, MaskKey};
use crate::core::{AdminReply, AdminRequest};

/// Apply one admin request to live core state. Immediate actions answer the
/// one-shot here; DROP transfers it into core-owned pending state until the
/// database verdict arrives.
pub(crate) fn handle(
    state: &mut ServerState,
    req: AdminRequest,
    reply: tokio::sync::oneshot::Sender<AdminReply>,
) {
    let outcome = match req {
        AdminRequest::AddServerBan {
            mask,
            kind,
            reason,
            actor,
        } => {
            return begin_add_ban(state, &mask, &kind, &reason, actor, reply);
        }
        AdminRequest::RemoveServerBan { mask, kind, actor } => {
            return begin_remove_ban(state, &mask, &kind, actor, reply);
        }
        AdminRequest::DropChannel { channel, actor } => {
            return begin_drop_channel(state, &channel, actor, reply);
        }
        AdminRequest::ListSessions => list_sessions(state, None),
        AdminRequest::Kill {
            nick,
            reason,
            actor,
        } => kill(state, &nick, &reason, &actor),
        AdminRequest::ListOwnSessions { account } => list_sessions(state, Some(&account)),
        AdminRequest::KillOwn {
            nick,
            reason,
            account,
        } => kill_own(state, &nick, &reason, &account),
    };
    let _ = reply.send(outcome);
}

/// Whether session `conn`'s authenticated account casefolds to `account`.
fn session_owned_by(state: &ServerState, conn: crate::core::ConnId, account: &str) -> bool {
    let want = state.casemap.casefold(account);
    state
        .sessions
        .get(&conn)
        .and_then(|s| s.account.as_deref())
        .is_some_and(|a| state.casemap.casefold(a) == want)
}

/// Snapshot registered sessions. With `only_account`, restrict to sessions
/// authenticated as that account (the caller's own connected clients).
fn list_sessions(state: &ServerState, only_account: Option<&str>) -> AdminReply {
    let want = only_account.map(|a| state.casemap.casefold(a));
    let mut sessions: Vec<crate::core::SessionInfo> = state
        .sessions
        .values()
        .filter(|s| s.is_registered())
        .filter(|s| match &want {
            None => true,
            Some(w) => s
                .account
                .as_deref()
                .is_some_and(|a| &state.casemap.casefold(a) == w),
        })
        .map(|s| {
            let mut channels: Vec<String> =
                s.channels.iter().map(|k| k.as_str().to_string()).collect();
            channels.sort();
            crate::core::SessionInfo {
                nick: s.nick().unwrap_or("*").to_string(),
                user: s.user().unwrap_or("*").to_string(),
                host: s.host.clone(),
                account: s.account.clone(),
                oper: s.oper,
                channels,
            }
        })
        .collect();
    sessions.sort_by_key(|s| s.nick.to_lowercase());
    AdminReply::Sessions(sessions)
}

fn kill(state: &mut ServerState, nick_in: &str, reason_in: &str, actor: &str) -> AdminReply {
    let comment = e6irc_proto::message::truncate_on_char_boundary(reason_in.trim(), 300);
    let comment = if comment.is_empty() {
        "Killed via admin console"
    } else {
        comment
    };
    if super::oper::kill_by_nick(state, nick_in, comment, actor) {
        AdminReply::Ok(format!("Killed {nick_in}"))
    } else {
        AdminReply::Err(format!("no such nick '{nick_in}'"))
    }
}

/// Self-service kill: disconnect `nick` only if that session is authenticated as
/// `account` (the caller). Refuses to touch a session that isn't the caller's,
/// so a non-admin cannot kill anyone else by guessing a nick.
fn kill_own(state: &mut ServerState, nick_in: &str, reason_in: &str, account: &str) -> AdminReply {
    let key = state.nick_key(nick_in);
    let Some(&conn) = state.nicks.get(&key) else {
        return AdminReply::Err(format!("no such session '{nick_in}'"));
    };
    if !session_owned_by(state, conn, account) {
        // Report as not-found rather than forbidden, so this can't be used to
        // probe which nicks exist / are signed in as other accounts.
        return AdminReply::Err(format!("no such session '{nick_in}'"));
    }
    let comment = e6irc_proto::message::truncate_on_char_boundary(reason_in.trim(), 300);
    let comment = if comment.is_empty() {
        "Disconnected from your account console"
    } else {
        comment
    };
    if super::oper::kill_by_nick(state, nick_in, comment, account) {
        AdminReply::Ok(format!("Disconnected {nick_in}"))
    } else {
        AdminReply::Err(format!("no such session '{nick_in}'"))
    }
}

fn begin_add_ban(
    state: &mut ServerState,
    mask_in: &str,
    kind_in: &str,
    reason_in: &str,
    actor: String,
    reply: tokio::sync::oneshot::Sender<AdminReply>,
) {
    let Some(kind) = BanKind::from_token(kind_in) else {
        let _ = reply.send(AdminReply::Err(format!(
            "unknown ban kind '{kind_in}' (want kline, dline or xline)"
        )));
        return;
    };
    // Reuse the oper mask normalization + netban ("matches everyone") refusal so
    // the console cannot set a wider ban than KLINE would allow.
    let parsed = match BanMask::parse(kind, &[mask_in], false) {
        Ok((parsed, _default_reason)) => parsed,
        Err(BanReject::MatchesEveryone(display)) => {
            let _ = reply.send(AdminReply::Err(format!(
                "refusing {} for {display}: it matches every user (use a more specific mask)",
                kind.label()
            )));
            return;
        }
    };
    let reason = e6irc_proto::message::truncate_on_char_boundary(reason_in.trim(), 300);
    let reason = if reason.is_empty() {
        "Banned via admin console"
    } else {
        reason
    };
    let mask = MaskKey::new(parsed.as_str(), state.casemap);
    if !state.config.sasl_enabled {
        let disconnected =
            apply_server_ban_hot(state, mask.clone(), kind, reason, &actor, kind.label());
        notify_opers(
            state,
            None,
            &format!(
                "{actor} (console) added {} for {} ({reason})",
                kind.label(),
                mask.as_str()
            ),
        );
        let _ = reply.send(AdminReply::Ok(format!(
            "Added {} for {} — {disconnected} session(s) disconnected",
            kind.label(),
            mask.as_str()
        )));
        return;
    }
    let mutation = crate::core::ServerBanMutation::Add {
        mask: mask.folded().to_string(),
        mask_display: mask.as_str().to_string(),
        reason: reason.to_string(),
        set_by: actor.clone(),
        kind: kind.as_str().to_string(),
    };
    queue_admin_server_ban(state, kind, mutation, actor, reply);
}

fn begin_remove_ban(
    state: &mut ServerState,
    mask_in: &str,
    kind_in: &str,
    actor: String,
    reply: tokio::sync::oneshot::Sender<AdminReply>,
) {
    let Some(kind) = BanKind::from_token(kind_in) else {
        let _ = reply.send(AdminReply::Err(format!(
            "unknown ban kind '{kind_in}' (want kline, dline or xline)"
        )));
        return;
    };
    // Fold like enforcement (mirror cmd_remove_ban) so a differently-cased
    // console removal still matches the stored ban.
    let mask = MaskKey::new(&ban_mask(kind, mask_in), state.casemap);
    if !state
        .server_bans
        .iter()
        .any(|ban| ban.kind == kind && ban.mask == mask)
    {
        let _ = reply.send(AdminReply::Err(format!(
            "no {} matching {}",
            kind.label(),
            mask.as_str()
        )));
        return;
    }
    if !state.config.sasl_enabled {
        remove_server_ban_hot(state, &mask, kind);
        let _ = reply.send(AdminReply::Ok(format!(
            "Removed {} for {}",
            kind.label(),
            mask.as_str()
        )));
        return;
    }
    let mutation = crate::core::ServerBanMutation::Remove {
        mask: mask.folded().to_string(),
        mask_display: mask.as_str().to_string(),
        kind: kind.as_str().to_string(),
        actor: actor.clone(),
    };
    queue_admin_server_ban(state, kind, mutation, actor, reply);
}

fn queue_admin_server_ban(
    state: &mut ServerState,
    kind: BanKind,
    mutation: crate::core::ServerBanMutation,
    actor: String,
    reply: tokio::sync::oneshot::Sender<AdminReply>,
) {
    let (mask, unavailable_action) = match &mutation {
        crate::core::ServerBanMutation::Add { mask_display, .. } => (mask_display.clone(), "added"),
        crate::core::ServerBanMutation::Remove { mask_display, .. } => {
            (mask_display.clone(), "removed")
        }
    };
    let Some(request_id) = state.admin_server_ban_id.checked_add(1) else {
        let _ = reply.send(AdminReply::Err("admin request ID space exhausted".into()));
        return;
    };
    let requester = crate::core::ServerBanRequester::Admin { request_id, actor };
    match queue_server_ban_mutation(state, mutation, requester) {
        Ok(()) => {
            state.admin_server_ban_id = request_id;
            state.pending_admin_server_bans.insert(request_id, reply);
        }
        Err(QueueServerBanError::AlreadyPending) => {
            let _ = reply.send(AdminReply::Err(format!(
                "a {} change for {mask} is already in progress",
                kind.label()
            )));
        }
        Err(QueueServerBanError::PersistenceUnavailable) => {
            let _ = reply.send(AdminReply::Err(format!(
                "persistence unavailable; server ban not {unavailable_action}"
            )));
        }
    }
}

fn begin_drop_channel(
    state: &mut ServerState,
    channel_in: &str,
    actor: String,
    reply: tokio::sync::oneshot::Sender<AdminReply>,
) {
    let Some(key) = state.chan_key_if_channel(channel_in) else {
        let _ = reply.send(AdminReply::Err(format!(
            "'{channel_in}' is not a channel name"
        )));
        return;
    };
    if !state.registered_founders.contains_key(&key) {
        let _ = reply.send(AdminReply::Err(format!(
            "{} is not a registered channel",
            key.as_str()
        )));
        return;
    }
    let Some(request_id) = state.admin_channel_drop_id.checked_add(1) else {
        let _ = reply.send(AdminReply::Err(
            "persistence unavailable; admin request ID space exhausted".into(),
        ));
        return;
    };
    let request = crate::core::DbRequest::DropChannel {
        channel: key.as_str().to_string(),
        requester: crate::core::ChannelDropRequester::Admin { request_id, actor },
    };
    if state.db_tx.try_push(request).is_err() {
        let _ = reply.send(AdminReply::Err(
            "persistence unavailable; channel not dropped".into(),
        ));
        return;
    }
    state.admin_channel_drop_id = request_id;
    state.pending_admin_channel_drops.insert(request_id, reply);
}
