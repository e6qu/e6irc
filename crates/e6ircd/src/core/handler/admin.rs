//! HTTP console/control-plane actions, run on the core thread via
//! [`crate::core::Input::Admin`].
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

/// Apply one HTTP control-plane request to live core state. Immediate actions
/// answer the one-shot here; durable channel/ban mutations transfer it into
/// core-owned pending state until the database verdict arrives.
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
        AdminRequest::RemoveServerBan {
            expected_id,
            mask,
            kind,
            actor,
        } => {
            return begin_remove_ban(state, expected_id, &mask, &kind, actor, reply);
        }
        AdminRequest::DropChannel { channel, actor } => {
            return begin_drop_channel(state, &channel, actor, reply);
        }
        AdminRequest::ListConnections { query } => list_connections(state, query),
        AdminRequest::DisconnectConnection {
            connection_id,
            reason,
            actor,
        } => disconnect_connection(state, connection_id, &reason, &actor),
        AdminRequest::DisconnectOwnConnection {
            connection_id,
            reason,
            account,
        } => disconnect_own_connection(state, connection_id, &reason, &account),
        AdminRequest::SetAccountSuspended {
            account,
            suspended,
            reason,
            actor,
        } => set_account_suspended(state, &account, suspended, &reason, &actor),
        AdminRequest::MutateOwnedChannel {
            channel,
            actor,
            mutation,
        } => {
            return begin_owned_channel_mutation(state, &channel, actor, mutation, reply);
        }
        AdminRequest::RegisterOwnedChannel { channel, actor } => {
            return begin_owned_channel_registration(state, &channel, actor, reply);
        }
    };
    let _ = reply.send(outcome);
}

fn set_account_suspended(
    state: &mut ServerState,
    account: &str,
    suspended: bool,
    reason: &str,
    actor: &str,
) -> AdminReply {
    let account_key = state.account_key(account);
    if !suspended {
        state.suspended_accounts.remove(&account_key);
        return AdminReply::Ok(format!("Reactivated live authentication for {account}"));
    }
    state.suspended_accounts.insert(account_key.clone());
    let connections: Vec<ConnId> = state
        .sessions
        .iter()
        .filter_map(|(connection, session)| {
            session
                .account
                .as_deref()
                .is_some_and(|candidate| state.account_key(candidate) == account_key)
                .then_some(*connection)
        })
        .collect();
    let mut disconnected = 0usize;
    for connection in connections {
        if super::oper::kill_connection(state, connection, reason, actor) {
            disconnected += 1;
        }
    }
    AdminReply::Ok(format!(
        "Disconnected {disconnected} live connection(s) for {account}"
    ))
}

fn begin_owned_channel_registration(
    state: &mut ServerState,
    channel_in: &str,
    actor: String,
    reply: tokio::sync::oneshot::Sender<AdminReply>,
) {
    let Some((key, reply)) = channel_request_key(state, channel_in, reply) else {
        return;
    };
    let Some(channel) = state.channels.get(&key) else {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::Conflict,
            format!("join {} before registering it", key.as_str()),
        ));
        return;
    };
    let actor_key = state.account_key(&actor);
    let operates_channel = channel.members().any(|(conn, member)| {
        member.op
            && state
                .sessions
                .get(&conn)
                .and_then(|session| session.account.as_deref())
                .is_some_and(|account| state.account_key(account) == actor_key)
    });
    if !operates_channel {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::Conflict,
            format!(
                "an identified session for {actor} must operate {}",
                channel.name
            ),
        ));
        return;
    }
    if state.registered_founders.contains_key(&key) {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::Conflict,
            format!("{} is already registered", channel.name),
        ));
        return;
    }
    if state.channel_registration_pending(&key) {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::Conflict,
            format!("registration of {} is already in progress", channel.name),
        ));
        return;
    }
    if state.channels_founded_by(&actor) >= super::channel::MAX_CHANNELS_PER_ACCOUNT {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::Conflict,
            "too many registered channels; unregister one before adding another",
        ));
        return;
    }
    let display = channel.name.clone();
    let topic = channel
        .topic
        .as_ref()
        .map(|topic| (topic.text.clone(), topic.set_by.clone(), topic.set_at_secs));
    if queue_channel_control(
        state,
        reply,
        "persistence unavailable; channel was not registered",
        move |request_id| crate::core::DbRequest::RegisterOwnedChannel {
            request_id,
            channel: display,
            founder_account: actor,
            topic,
        },
    ) {
        state.pending_channel_registrations.insert(key, actor_key);
    }
}

fn begin_owned_channel_mutation(
    state: &mut ServerState,
    channel_in: &str,
    actor: String,
    mutation: crate::core::ChannelMutation,
    reply: tokio::sync::oneshot::Sender<AdminReply>,
) {
    let Some((key, reply)) = channel_request_key(state, channel_in, reply) else {
        return;
    };
    if !state.is_founder(&key, &actor) {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::NotFound,
            format!("{} is not a channel you own", key.as_str()),
        ));
        return;
    }
    let persisted = match normalize_channel_mutation(state, &key, &actor, mutation) {
        Ok(mutation) => mutation,
        Err(message) => {
            let _ = reply.send(channel_error(
                crate::core::ChannelControlError::Invalid,
                message,
            ));
            return;
        }
    };
    queue_channel_control(
        state,
        reply,
        "persistence unavailable; channel was not changed",
        move |request_id| crate::core::DbRequest::MutateOwnedChannel {
            request_id,
            channel: key.as_str().to_string(),
            actor,
            mutation: persisted,
        },
    );
}

fn channel_request_key(
    state: &ServerState,
    channel_in: &str,
    reply: tokio::sync::oneshot::Sender<AdminReply>,
) -> Option<(ChanKey, tokio::sync::oneshot::Sender<AdminReply>)> {
    match state.chan_key_if_channel(channel_in) {
        Some(key) => Some((key, reply)),
        None => {
            let _ = reply.send(channel_error(
                crate::core::ChannelControlError::Invalid,
                format!("'{channel_in}' is not a channel name"),
            ));
            None
        }
    }
}

fn queue_channel_control(
    state: &mut ServerState,
    reply: tokio::sync::oneshot::Sender<AdminReply>,
    queue_failure: &'static str,
    make_request: impl FnOnce(u64) -> crate::core::DbRequest,
) -> bool {
    let Some(request_id) = state.channel_control_id.checked_add(1) else {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::Unavailable,
            "persistence unavailable; channel request ID space exhausted",
        ));
        return false;
    };
    if state.db_tx.try_push(make_request(request_id)).is_err() {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::Unavailable,
            queue_failure,
        ));
        return false;
    }
    state.channel_control_id = request_id;
    state.pending_channel_controls.insert(request_id, reply);
    true
}

fn channel_error(kind: crate::core::ChannelControlError, message: impl Into<String>) -> AdminReply {
    AdminReply::ChannelErr {
        kind,
        message: message.into(),
    }
}

fn normalize_channel_mutation(
    state: &ServerState,
    key: &ChanKey,
    actor: &str,
    mutation: crate::core::ChannelMutation,
) -> Result<crate::core::PersistedChannelMutation, String> {
    use crate::core::{ChannelMutation, PersistedChannelMutation};
    match mutation {
        ChannelMutation::SetTopic { topic } => {
            let topic = match topic {
                None => None,
                Some(raw) => {
                    if raw.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
                        return Err("topic contains a forbidden line-control byte".into());
                    }
                    if raw.len() > super::channel::TOPICLEN {
                        return Err(format!(
                            "topic exceeds the {}-byte limit",
                            super::channel::TOPICLEN
                        ));
                    }
                    let display = state
                        .channels
                        .get(key)
                        .map_or(key.as_str(), |channel| channel.name.as_str());
                    let fitted = super::fit_trailing(
                        &format!(":{} TOPIC {display} :", state.config.server_name),
                        &raw,
                    );
                    (!fitted.is_empty()).then(|| {
                        (
                            fitted.to_string(),
                            actor.to_string(),
                            (state.config.clock)().as_secs(),
                        )
                    })
                }
            };
            Ok(PersistedChannelMutation::SetTopic { topic })
        }
        ChannelMutation::SetKeeptopic { enabled } => {
            let effective = state
                .pending_channel_topics
                .get(key)
                .map(|(_, topic)| topic.clone())
                .unwrap_or_else(|| {
                    state
                        .channels
                        .get(key)
                        .and_then(|channel| channel.topic.clone())
                        .or_else(|| state.registered_topics.get(key).cloned())
                });
            Ok(PersistedChannelMutation::SetKeeptopic {
                enabled,
                topic: enabled
                    .then_some(effective)
                    .flatten()
                    .map(|topic| (topic.text, topic.set_by, topic.set_at_secs)),
            })
        }
        ChannelMutation::SetMlock { mlock } => {
            let mlock = match mlock {
                None => None,
                Some(spec) => {
                    let parsed = crate::core::state::MlockModes::parse(spec.trim())
                        .map_err(|bad| format!("'{bad}' is not a lockable mode"))?;
                    if parsed.is_empty() {
                        None
                    } else {
                        Some(parsed.render())
                    }
                }
            };
            Ok(PersistedChannelMutation::SetMlock { mlock })
        }
        ChannelMutation::SetAccess { account, flags } => {
            if account.is_empty() || account.len() > 64 {
                return Err("account must contain 1–64 bytes".into());
            }
            let flags = match flags {
                None => None,
                Some(flags) => Some(
                    match flags.as_str() {
                        "o" => "o",
                        "v" => "v",
                        "ov" | "vo" => "ov",
                        _ => return Err("access flags must be one of o, v, ov, or vo".into()),
                    }
                    .to_string(),
                ),
            };
            Ok(PersistedChannelMutation::SetAccess { account, flags })
        }
        ChannelMutation::TransferFounder { account } => {
            if account.is_empty() || account.len() > 64 {
                return Err("new founder must contain 1–64 bytes".into());
            }
            Ok(PersistedChannelMutation::TransferFounder {
                account: state.casemap.casefold(&account),
            })
        }
        ChannelMutation::Drop => Ok(PersistedChannelMutation::Drop),
    }
}

/// Return the registered session's nick only when its authenticated account
/// casefolds to `account`.
fn owned_session_nick(
    state: &ServerState,
    conn: crate::core::ConnId,
    account: &str,
) -> Option<String> {
    let want = state.casemap.casefold(account);
    state
        .sessions
        .get(&conn)
        .filter(|session| session.is_registered())
        .filter(|session| {
            session
                .account
                .as_deref()
                .is_some_and(|session_account| state.casemap.casefold(session_account) == want)
        })
        .and_then(|session| session.nick())
        .map(str::to_owned)
}

struct FoldedLiveConnectionFilter {
    nick: Option<String>,
    account: Option<String>,
    transport: Option<crate::core::ConnectionTransport>,
    oper: Option<bool>,
}

fn live_connection_matches(
    state: &ServerState,
    session: &crate::core::state::Session,
    filter: &FoldedLiveConnectionFilter,
) -> bool {
    if !session.is_registered() {
        return false;
    }
    if let Some(want) = filter.nick.as_deref()
        && !session
            .nick()
            .is_some_and(|nick| state.casemap.casefold(nick) == want)
    {
        return false;
    }
    if let Some(want) = filter.account.as_deref()
        && !session
            .account
            .as_deref()
            .is_some_and(|account| state.casemap.casefold(account) == want)
    {
        return false;
    }
    if filter
        .transport
        .is_some_and(|transport| session.transport != transport)
    {
        return false;
    }
    if filter.oper.is_some_and(|oper| session.oper != oper) {
        return false;
    }
    true
}

/// Build a newest-first live-connection page while retaining at most one page
/// plus its cursor sentinel. The core still examines live state once, but a
/// request can never allocate a vector proportional to the whole server.
fn list_connections(state: &ServerState, query: crate::core::LiveConnectionQuery) -> AdminReply {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    let page_size = query.page_size.value();
    let fetch_limit = page_size + 1;
    let filter = FoldedLiveConnectionFilter {
        nick: query
            .exact_nick
            .as_deref()
            .map(|nick| state.casemap.casefold(nick)),
        account: query
            .exact_account
            .as_deref()
            .map(|account| state.casemap.casefold(account)),
        transport: query.transport,
        oper: query.oper,
    };
    let mut newest = BinaryHeap::with_capacity(fetch_limit + 1);
    for (&connection_id, session) in &state.sessions {
        if query
            .before_id
            .is_some_and(|before_id| connection_id.0 >= before_id)
            || !live_connection_matches(state, session, &filter)
        {
            continue;
        }
        newest.push(Reverse(connection_id.0));
        if newest.len() > fetch_limit {
            newest.pop();
        }
    }
    let now = (state.config.mono_clock)();
    let mut connection_ids: Vec<u64> = newest
        .into_iter()
        .map(|Reverse(connection_id)| connection_id)
        .collect();
    connection_ids.sort_unstable_by(|left, right| right.cmp(left));
    let next_before_id = (connection_ids.len() > page_size).then(|| connection_ids[page_size - 1]);
    connection_ids.truncate(page_size);
    let entries = connection_ids
        .into_iter()
        .map(|connection_id| {
            let session = &state.sessions[&crate::core::ConnId(connection_id)];
            let mut channels: Vec<String> = session
                .channels
                .iter()
                .map(|channel| channel.as_str().to_string())
                .collect();
            channels.sort();
            crate::core::LiveConnectionInfo {
                id: connection_id,
                nick: session.nick().unwrap_or("*").to_string(),
                user: session.user().unwrap_or("*").to_string(),
                host: session.host.clone(),
                account: session.account.clone(),
                oper: session.oper,
                transport: session.transport,
                connected_at: session.signon,
                idle_seconds: now.saturating_sub(session.last_active).as_secs(),
                channels,
            }
        })
        .collect();
    AdminReply::Connections(crate::core::LiveConnectionPage {
        entries,
        next_before_id,
    })
}

fn disconnect_connection(
    state: &mut ServerState,
    connection_id: u64,
    reason_in: &str,
    actor: &str,
) -> AdminReply {
    let comment = e6irc_proto::message::truncate_on_char_boundary(reason_in.trim(), 300);
    let comment = if comment.is_empty() {
        "Administrative disconnect"
    } else {
        comment
    };
    let connection = crate::core::ConnId(connection_id);
    let nick = state
        .sessions
        .get(&connection)
        .and_then(|session| session.nick())
        .map(str::to_owned);
    if super::oper::kill_connection(state, connection, comment, actor) {
        AdminReply::Ok(format!(
            "Disconnected {}",
            nick.as_deref().unwrap_or("connection")
        ))
    } else {
        AdminReply::ConnectionMissing
    }
}

/// Self-service disconnect: the immutable id must still name a registered
/// connection authenticated as the caller. A stale id can never resolve to a
/// later connection, unlike a nick that may have been released and reused.
fn disconnect_own_connection(
    state: &mut ServerState,
    connection_id: u64,
    reason_in: &str,
    account: &str,
) -> AdminReply {
    let connection = crate::core::ConnId(connection_id);
    let Some(nick) = owned_session_nick(state, connection, account) else {
        // Report as not-found rather than forbidden, so this can't be used to
        // probe which connections exist or belong to other accounts.
        return AdminReply::ConnectionMissing;
    };
    let comment = e6irc_proto::message::truncate_on_char_boundary(reason_in.trim(), 300);
    let comment = if comment.is_empty() {
        "Disconnected by account owner"
    } else {
        comment
    };
    if super::oper::kill_connection(state, connection, comment, account) {
        AdminReply::Ok(format!("Disconnected {nick}"))
    } else {
        AdminReply::ConnectionMissing
    }
}

fn err_unknown_ban_kind(kind_in: &str) -> AdminReply {
    ban_error(
        crate::core::BanControlError::Invalid,
        format!("unknown ban kind '{kind_in}' (want kline, dline or xline)"),
    )
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
        let _ = reply.send(err_unknown_ban_kind(kind_in));
        return;
    };
    // Reuse the oper mask normalization + netban ("matches everyone") refusal so
    // the console cannot set a wider ban than KLINE would allow.
    let parsed =
        match BanMask::parse(kind, &[mask_in], false) {
            Ok((parsed, _default_reason)) => parsed,
            Err(BanReject::MatchesEveryone(display)) => {
                let _ = reply.send(ban_error(crate::core::BanControlError::Invalid, format!(
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
    let mutation =
        crate::core::ServerBanMutation::add(&mask, kind, reason.to_string(), actor.clone());
    queue_admin_server_ban(state, kind, mutation, actor, reply);
}

fn begin_remove_ban(
    state: &mut ServerState,
    expected_id: Option<i64>,
    mask_in: &str,
    kind_in: &str,
    actor: String,
    reply: tokio::sync::oneshot::Sender<AdminReply>,
) {
    let Some(kind) = BanKind::from_token(kind_in) else {
        let _ = reply.send(ban_error(
            crate::core::BanControlError::Invalid,
            format!("unknown server-ban kind {kind_in}"),
        ));
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
        let _ = reply.send(ban_error(
            crate::core::BanControlError::NotFound,
            format!("no {} matching {}", kind.label(), mask.as_str()),
        ));
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
    let mutation =
        crate::core::ServerBanMutation::remove_with_id(&mask, kind, actor.clone(), expected_id);
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
        let _ = reply.send(ban_error(
            crate::core::BanControlError::Unavailable,
            "admin request ID space exhausted",
        ));
        return;
    };
    let requester = crate::core::ServerBanRequester::Admin { request_id, actor };
    match queue_server_ban_mutation(state, mutation, requester) {
        Ok(()) => {
            state.admin_server_ban_id = request_id;
            state.pending_admin_server_bans.insert(request_id, reply);
        }
        Err(QueueServerBanError::AlreadyPending) => {
            let _ = reply.send(ban_error(
                crate::core::BanControlError::Conflict,
                format!(
                    "a {} change for {mask} is already in progress",
                    kind.label()
                ),
            ));
        }
        Err(QueueServerBanError::PersistenceUnavailable) => {
            let _ = reply.send(ban_error(
                crate::core::BanControlError::Unavailable,
                format!("persistence unavailable; server ban not {unavailable_action}"),
            ));
        }
    }
}

fn ban_error(kind: crate::core::BanControlError, message: impl Into<String>) -> AdminReply {
    AdminReply::BanErr {
        kind,
        message: message.into(),
    }
}

fn begin_drop_channel(
    state: &mut ServerState,
    channel_in: &str,
    actor: String,
    reply: tokio::sync::oneshot::Sender<AdminReply>,
) {
    let Some(key) = state.chan_key_if_channel(channel_in) else {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::Invalid,
            format!("'{channel_in}' is not a channel name"),
        ));
        return;
    };
    if !state.registered_founders.contains_key(&key) {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::NotFound,
            format!("{} is not a registered channel", key.as_str()),
        ));
        return;
    }
    let Some(request_id) = state.admin_channel_drop_id.checked_add(1) else {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::Unavailable,
            "persistence unavailable; admin request ID space exhausted",
        ));
        return;
    };
    let request = crate::core::DbRequest::DropChannel {
        channel: key.as_str().to_string(),
        requester: crate::core::ChannelDropRequester::Admin { request_id, actor },
    };
    if state.db_tx.try_push(request).is_err() {
        let _ = reply.send(channel_error(
            crate::core::ChannelControlError::Unavailable,
            "persistence unavailable; channel not dropped",
        ));
        return;
    }
    state.admin_channel_drop_id = request_id;
    state.pending_admin_channel_drops.insert(request_id, reply);
}

pub(crate) fn channel_control_result(
    state: &mut ServerState,
    request_id: u64,
    channel: String,
    mutation: crate::core::PersistedChannelMutation,
    result: crate::core::ChannelControlResult,
) {
    use crate::core::{ChannelControlError, ChannelControlResult, PersistedChannelMutation};

    let key = state.chan_key(&channel);
    let response = match result {
        ChannelControlResult::Applied => {
            let summary = match mutation {
                PersistedChannelMutation::SetTopic { topic } => {
                    let live_topic = topic.map(|(text, set_by, set_at_secs)| Topic {
                        text,
                        set_by,
                        set_at_secs,
                    });
                    match &live_topic {
                        Some(topic) => {
                            state.registered_topics.insert(key.clone(), topic.clone());
                        }
                        None => {
                            state.registered_topics.remove(&key);
                        }
                    }
                    if let Some(channel_state) = state.channels.get_mut(&key) {
                        channel_state.topic = live_topic.clone();
                        let display = channel_state.name.clone();
                        let text = live_topic.as_ref().map_or("", |topic| topic.text.as_str());
                        let line = format!(":{} TOPIC {display} :{text}", state.config.server_name);
                        state.broadcast_channel(&key, &line, None);
                    }
                    format!("Updated the retained topic for {}", key.as_str())
                }
                PersistedChannelMutation::SetKeeptopic { enabled, topic } => {
                    if enabled {
                        state.keeptopic_off.remove(&key);
                        match topic {
                            Some((text, set_by, set_at_secs)) => {
                                state.registered_topics.insert(
                                    key.clone(),
                                    Topic {
                                        text,
                                        set_by,
                                        set_at_secs,
                                    },
                                );
                            }
                            None => {
                                state.registered_topics.remove(&key);
                            }
                        }
                    } else {
                        state.keeptopic_off.insert(key.clone());
                        state.registered_topics.remove(&key);
                    }
                    format!(
                        "Turned KEEPTOPIC {} for {}",
                        if enabled { "on" } else { "off" },
                        key.as_str()
                    )
                }
                PersistedChannelMutation::SetMlock { mlock } => {
                    match mlock.as_deref() {
                        Some(spec) => match crate::core::state::MlockModes::parse(spec) {
                            Ok(modes) => {
                                state.channel_mlock.insert(key.clone(), modes);
                                super::channel::apply_mlock(state, &key);
                            }
                            Err(bad) => {
                                eprintln!(
                                    "core: database echoed invalid canonical MLOCK character {bad:?}"
                                );
                                return finish_channel_control(
                                    state,
                                    request_id,
                                    channel_error(
                                        ChannelControlError::Unavailable,
                                        "persistence returned an invalid mode lock",
                                    ),
                                );
                            }
                        },
                        None => {
                            state.channel_mlock.remove(&key);
                        }
                    }
                    format!("Updated the mode lock for {}", key.as_str())
                }
                PersistedChannelMutation::SetAccess { account, flags } => {
                    let account_key = state.account_key(&account);
                    match flags {
                        Some(flags) => {
                            state
                                .channel_access
                                .entry(key.clone())
                                .or_default()
                                .insert(account_key, flags);
                        }
                        None => {
                            if let Some(entries) = state.channel_access.get_mut(&key) {
                                entries.remove(&account_key);
                                if entries.is_empty() {
                                    state.channel_access.remove(&key);
                                }
                            }
                        }
                    }
                    format!("Updated {account}'s access on {}", key.as_str())
                }
                PersistedChannelMutation::TransferFounder { account } => {
                    state
                        .registered_founders
                        .insert(key.clone(), state.account_key(&account));
                    format!("Transferred {} to {account}", key.as_str())
                }
                PersistedChannelMutation::Drop => {
                    super::services::clear_registered_channel(state, &key);
                    format!("Unregistered {}", key.as_str())
                }
            };
            AdminReply::Ok(summary)
        }
        ChannelControlResult::MissingOrNotOwner => channel_error(
            ChannelControlError::NotFound,
            format!(
                "{} no longer exists or is no longer owned by this account",
                key.as_str()
            ),
        ),
        ChannelControlResult::AccountMissing => channel_error(
            ChannelControlError::NotFound,
            "the target account is not registered",
        ),
        ChannelControlResult::AccessLimitReached => channel_error(
            ChannelControlError::Conflict,
            "the channel access list is full; remove an entry before adding another",
        ),
        ChannelControlResult::KeeptopicDisabled => channel_error(
            ChannelControlError::Conflict,
            "turn KEEPTOPIC on before setting a retained topic",
        ),
        ChannelControlResult::Unavailable => channel_error(
            ChannelControlError::Unavailable,
            "persistence unavailable; channel was not changed",
        ),
    };
    finish_channel_control(state, request_id, response);
}

pub(crate) fn owned_channel_registration_result(
    state: &mut ServerState,
    request_id: u64,
    channel: String,
    founder_account: String,
    topic: Option<(String, String, u64)>,
    result: crate::core::ChannelRegistrationResult,
) {
    use crate::core::{ChannelControlError, ChannelRegistrationResult};

    let key = state.chan_key(&channel);
    state.pending_channel_registrations.remove(&key);
    let response = match result {
        ChannelRegistrationResult::Registered => {
            state.set_founder(&channel, &founder_account);
            replace_registered_topic(state, &key, topic);
            AdminReply::Ok(format!("Registered {channel} to {founder_account}"))
        }
        ChannelRegistrationResult::Exists => channel_error(
            ChannelControlError::Conflict,
            format!("{channel} is already registered"),
        ),
        ChannelRegistrationResult::AccountMissing => channel_error(
            ChannelControlError::NotFound,
            "the founder account is no longer registered",
        ),
        ChannelRegistrationResult::Unavailable => channel_error(
            ChannelControlError::Unavailable,
            "persistence unavailable; channel was not registered",
        ),
    };
    finish_channel_control(state, request_id, response);
}

fn finish_channel_control(state: &mut ServerState, request_id: u64, response: AdminReply) {
    match state.pending_channel_controls.remove(&request_id) {
        Some(reply) => {
            let _ = reply.send(response);
        }
        None => {
            eprintln!("core: channel-control verdict for unknown request {request_id}");
        }
    }
}
