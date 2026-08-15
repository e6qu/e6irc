// SPDX-License-Identifier: Apache-2.0

//! Founder-owned registered-channel REST control plane.

use super::*;

#[derive(serde::Serialize)]
struct OwnedChannelResponse {
    name: String,
    founder: String,
    keeptopic: bool,
    topic: Option<String>,
    topic_setter: Option<String>,
    topic_set_at: Option<i64>,
    mlock: Option<String>,
    access: Vec<ChannelAccessResponse>,
}

#[derive(serde::Serialize)]
struct ChannelAccessResponse {
    account: String,
    flags: String,
}

#[derive(serde::Serialize)]
struct OwnedChannelListResponse {
    channels: Vec<OwnedChannelResponse>,
}

#[derive(serde::Serialize)]
struct ChannelControlResponse {
    ok: ChannelControlSuccess,
    detail: String,
}

struct ChannelControlSuccess;

impl serde::Serialize for ChannelControlSuccess {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(true)
    }
}

fn channel_response(channel: crate::db::OwnedChannel) -> OwnedChannelResponse {
    OwnedChannelResponse {
        name: channel.name,
        founder: channel.founder,
        keeptopic: channel.keeptopic,
        topic: channel.topic,
        topic_setter: channel.topic_setter,
        topic_set_at: channel.topic_set_at_millis,
        mlock: channel.mlock,
        access: channel
            .access
            .into_iter()
            .map(|entry| ChannelAccessResponse {
                account: entry.account,
                flags: entry.flags,
            })
            .collect(),
    }
}

pub(super) async fn list_owned_channels(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
) -> Response {
    match crate::db::list_owned_channels(pool_of(&state), &account).await {
        Ok(channels) => json_no_store(OwnedChannelListResponse {
            channels: channels.into_iter().map(channel_response).collect(),
        }),
        Err(error) => {
            eprintln!("http: owned channel list failed: {error}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegisterChannelBody {
    name: String,
}

pub(super) async fn register_owned_channel(
    State(state): State<Arc<AppState>>,
    Authenticated(actor): Authenticated,
    JsonBody(body): JsonBody<RegisterChannelBody>,
) -> Response {
    let request = crate::core::AdminRequest::RegisterOwnedChannel {
        channel: body.name,
        actor,
    };
    control_response(&state, request, StatusCode::CREATED).await
}

pub(super) async fn get_owned_channel(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    Path(name): Path<String>,
) -> Response {
    let folded = e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&name);
    match crate::db::list_owned_channels(pool_of(&state), &account).await {
        Ok(channels) => match channels.into_iter().find(|channel| {
            e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(&channel.name) == folded
        }) {
            Some(channel) => json_no_store(channel_response(channel)),
            None => problem(StatusCode::NOT_FOUND, "No such owned channel", None),
        },
        Err(error) => {
            eprintln!("http: owned channel read failed: {error}");
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable",
                None,
            )
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ChannelPatch {
    SetTopic { topic: Option<String> },
    SetKeeptopic { enabled: bool },
    SetMlock { mlock: Option<String> },
    TransferFounder { account: String },
}

impl ChannelPatch {
    fn into_mutation(self) -> crate::core::ChannelMutation {
        match self {
            Self::SetTopic { topic } => crate::core::ChannelMutation::SetTopic { topic },
            Self::SetKeeptopic { enabled } => {
                crate::core::ChannelMutation::SetKeeptopic { enabled }
            }
            Self::SetMlock { mlock } => crate::core::ChannelMutation::SetMlock { mlock },
            Self::TransferFounder { account } => {
                crate::core::ChannelMutation::TransferFounder { account }
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccessBody {
    flags: String,
}

pub(super) async fn patch_owned_channel(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    Path(name): Path<String>,
    JsonBody(patch): JsonBody<ChannelPatch>,
) -> Response {
    mutate_response(&state, name, account, patch.into_mutation()).await
}

pub(super) async fn delete_owned_channel(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
    Path(name): Path<String>,
) -> Response {
    mutate_response(&state, name, account, crate::core::ChannelMutation::Drop).await
}

/// Unregister a channel through the administrator control plane. This remains
/// core-owned so the durable deletion, live registration state, and audit
/// outcome commit in the same ordered transition as the IRC services command.
pub(super) async fn delete_admin_channel(
    State(state): State<Arc<AppState>>,
    AdminAccount(actor): AdminAccount,
    Path(name): Path<String>,
) -> Response {
    match core_reply(
        &state,
        crate::core::AdminRequest::DropChannel {
            channel: name,
            actor,
        },
    )
    .await
    {
        Ok(crate::core::AdminReply::Ok(_)) => StatusCode::NO_CONTENT.into_response(),
        Ok(crate::core::AdminReply::ChannelErr { kind, message }) => {
            channel_error_response(kind, message, "No such registered channel")
        }
        Ok(_) | Err(_) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Channel control unavailable",
            None,
        ),
    }
}

pub(super) async fn put_channel_access(
    State(state): State<Arc<AppState>>,
    Authenticated(owner): Authenticated,
    Path((name, account)): Path<(String, String)>,
    JsonBody(body): JsonBody<AccessBody>,
) -> Response {
    access_response(&state, name, owner, account, Some(body.flags)).await
}

pub(super) async fn delete_channel_access(
    State(state): State<Arc<AppState>>,
    Authenticated(owner): Authenticated,
    Path((name, account)): Path<(String, String)>,
) -> Response {
    access_response(&state, name, owner, account, None).await
}

async fn access_response(
    state: &AppState,
    channel: String,
    owner: String,
    account: String,
    flags: Option<String>,
) -> Response {
    mutate_response(
        state,
        channel,
        owner,
        crate::core::ChannelMutation::SetAccess { account, flags },
    )
    .await
}

async fn mutate_response(
    state: &AppState,
    channel: String,
    actor: String,
    mutation: crate::core::ChannelMutation,
) -> Response {
    let request = crate::core::AdminRequest::MutateOwnedChannel {
        channel,
        actor,
        mutation,
    };
    control_response(state, request, StatusCode::OK).await
}

async fn control_response(
    state: &AppState,
    request: crate::core::AdminRequest,
    success: StatusCode,
) -> Response {
    match core_reply(state, request).await {
        Ok(crate::core::AdminReply::Ok(detail)) => (
            success,
            axum::Json(ChannelControlResponse {
                ok: ChannelControlSuccess,
                detail,
            }),
        )
            .into_response(),
        Ok(crate::core::AdminReply::ChannelErr { kind, message }) => {
            channel_error_response(kind, message, "No such owned channel")
        }
        Ok(crate::core::AdminReply::Err(message)) => problem(
            StatusCode::CONFLICT,
            "Channel change rejected",
            Some(&message),
        ),
        Ok(
            crate::core::AdminReply::BanErr { .. }
            | crate::core::AdminReply::Connections(_)
            | crate::core::AdminReply::ConnectionMissing,
        ) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unexpected core response",
            None,
        ),
        Err(message) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "Core unavailable",
            Some(&message),
        ),
    }
}

fn channel_error_response(
    kind: crate::core::ChannelControlError,
    message: String,
    not_found_title: &'static str,
) -> Response {
    let (status, title) = match kind {
        crate::core::ChannelControlError::Invalid => {
            (StatusCode::BAD_REQUEST, "Invalid channel change")
        }
        crate::core::ChannelControlError::NotFound => (StatusCode::NOT_FOUND, not_found_title),
        crate::core::ChannelControlError::Conflict => {
            (StatusCode::CONFLICT, "Channel change conflict")
        }
        crate::core::ChannelControlError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Channel control unavailable",
        ),
    };
    problem(status, title, Some(&message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_channel_control_cannot_serialize_a_false_result() {
        let response = serde_json::to_string(&ChannelControlResponse {
            ok: ChannelControlSuccess,
            detail: "updated".into(),
        })
        .expect("channel control response");
        assert_eq!(response, r#"{"ok":true,"detail":"updated"}"#);
    }
}
