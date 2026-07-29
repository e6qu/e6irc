// SPDX-License-Identifier: Apache-2.0

//! Founder-owned registered-channel REST control plane.

use super::*;

fn channel_json(channel: crate::db::OwnedChannel) -> serde_json::Value {
    serde_json::json!({
        "name": channel.name,
        "founder": channel.founder,
        "keeptopic": channel.keeptopic,
        "topic": channel.topic,
        "topic_setter": channel.topic_setter,
        "topic_set_at": channel.topic_set_at_millis,
        "mlock": channel.mlock,
        "access": channel.access.into_iter().map(|entry| serde_json::json!({
            "account": entry.account,
            "flags": entry.flags,
        })).collect::<Vec<_>>(),
    })
}

pub(super) async fn list_owned_channels(
    State(state): State<Arc<AppState>>,
    Authenticated(account): Authenticated,
) -> Response {
    match crate::db::list_owned_channels(pool_of(&state), &account).await {
        Ok(channels) => (
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "channels": channels.into_iter().map(channel_json).collect::<Vec<_>>()
            })
            .to_string(),
        )
            .into_response(),
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
            Some(channel) => (
                [(header::CONTENT_TYPE, "application/json")],
                channel_json(channel).to_string(),
            )
                .into_response(),
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
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "ok": true, "detail": detail }).to_string(),
        )
            .into_response(),
        Ok(crate::core::AdminReply::ChannelErr { kind, message }) => {
            let (status, title) = match kind {
                crate::core::ChannelControlError::Invalid => {
                    (StatusCode::BAD_REQUEST, "Invalid channel change")
                }
                crate::core::ChannelControlError::NotFound => {
                    (StatusCode::NOT_FOUND, "No such owned channel")
                }
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
        Ok(crate::core::AdminReply::Err(message)) => problem(
            StatusCode::CONFLICT,
            "Channel change rejected",
            Some(&message),
        ),
        Ok(
            crate::core::AdminReply::Connections(_) | crate::core::AdminReply::ConnectionMissing,
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
