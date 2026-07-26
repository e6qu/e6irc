//! HTTP admin-console actions, run on the core thread via [`crate::core::Input::Admin`].
//!
//! Each action reuses the exact live-state + persistence path of the equivalent
//! IRC oper/services command (extracted into shared helpers), so a console
//! action behaves identically to its IRC counterpart — same hot-list update,
//! same disconnection of matching sessions, same audit row — rather than a
//! second, divergent implementation.

use super::oper::{
    BanMask, BanReject, apply_server_ban, ban_mask, notify_opers, record_audit_by,
    remove_server_ban,
};
use super::services::drop_registered_channel;
use super::*;
use crate::core::state::{BanKind, MaskKey};
use crate::core::{AdminReply, AdminRequest};

/// Apply one admin request to live core state and return its outcome.
pub(crate) fn handle(state: &mut ServerState, req: AdminRequest) -> AdminReply {
    match req {
        AdminRequest::AddServerBan {
            mask,
            kind,
            reason,
            actor,
        } => add_ban(state, &mask, &kind, &reason, &actor),
        AdminRequest::RemoveServerBan { mask, kind, actor } => {
            remove_ban(state, &mask, &kind, &actor)
        }
        AdminRequest::DropChannel { channel, actor } => drop_channel(state, &channel, &actor),
    }
}

fn add_ban(
    state: &mut ServerState,
    mask_in: &str,
    kind_in: &str,
    reason_in: &str,
    actor: &str,
) -> AdminReply {
    let Some(kind) = BanKind::from_token(kind_in) else {
        return AdminReply::Err(format!(
            "unknown ban kind '{kind_in}' (want kline, dline or xline)"
        ));
    };
    // Reuse the oper mask normalization + netban ("matches everyone") refusal so
    // the console cannot set a wider ban than KLINE would allow.
    let parsed = match BanMask::parse(kind, &[mask_in], false) {
        Ok((parsed, _default_reason)) => parsed,
        Err(BanReject::MatchesEveryone(display)) => {
            return AdminReply::Err(format!(
                "refusing {} for {display}: it matches every user (use a more specific mask)",
                kind.label()
            ));
        }
    };
    let reason = e6irc_proto::message::truncate_on_char_boundary(reason_in.trim(), 300);
    let reason = if reason.is_empty() {
        "Banned via admin console"
    } else {
        reason
    };
    let mask = MaskKey::new(parsed.as_str(), state.casemap);
    // Audit before the apply: apply_server_ban disconnects matching sessions.
    record_audit_by(
        state,
        actor,
        &kind.as_str().to_uppercase(),
        mask.as_str(),
        reason,
    );
    let disconnected = apply_server_ban(state, mask.clone(), kind, reason, actor, kind.label());
    notify_opers(
        state,
        None,
        &format!(
            "{actor} (console) added {} for {} ({reason})",
            kind.label(),
            mask.as_str()
        ),
    );
    AdminReply::Ok(format!(
        "Added {} for {} — {disconnected} session(s) disconnected",
        kind.label(),
        mask.as_str()
    ))
}

fn remove_ban(state: &mut ServerState, mask_in: &str, kind_in: &str, actor: &str) -> AdminReply {
    let Some(kind) = BanKind::from_token(kind_in) else {
        return AdminReply::Err(format!(
            "unknown ban kind '{kind_in}' (want kline, dline or xline)"
        ));
    };
    // Fold like enforcement (mirror cmd_remove_ban) so a differently-cased
    // console removal still matches the stored ban.
    let mask = MaskKey::new(&ban_mask(kind, mask_in), state.casemap);
    if remove_server_ban(state, &mask, kind) {
        record_audit_by(
            state,
            actor,
            &format!("UN{}", kind.as_str().to_uppercase()),
            mask.as_str(),
            "",
        );
        AdminReply::Ok(format!("Removed {} for {}", kind.label(), mask.as_str()))
    } else {
        AdminReply::Err(format!("no {} matching {}", kind.label(), mask.as_str()))
    }
}

fn drop_channel(state: &mut ServerState, channel_in: &str, actor: &str) -> AdminReply {
    let Some(key) = state.chan_key_if_channel(channel_in) else {
        return AdminReply::Err(format!("'{channel_in}' is not a channel name"));
    };
    if !state.registered_founders.contains_key(&key) {
        return AdminReply::Err(format!("{} is not a registered channel", key.as_str()));
    }
    if !drop_registered_channel(state, &key) {
        return AdminReply::Err("persistence unavailable; channel not dropped".into());
    }
    record_audit_by(state, actor, "DROPCHAN", key.as_str(), "");
    AdminReply::Ok(format!("Unregistered {}", key.as_str()))
}
