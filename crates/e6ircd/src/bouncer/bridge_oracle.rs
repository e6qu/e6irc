//! In-process Discord and Slack protocol oracle.

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde::Serialize;

#[derive(Serialize)]
struct Empty {}

#[derive(Serialize)]
struct DiscordChannel {
    name: &'static str,
}

#[derive(Serialize)]
struct DiscordGateway {
    url: String,
}

#[derive(Serialize)]
struct SlackError {
    ok: bool,
    error: &'static str,
}

#[derive(Serialize)]
struct SlackChannel {
    ok: bool,
    channel: SlackChannelData,
}

#[derive(Serialize)]
struct SlackChannelData {
    name: &'static str,
}

#[derive(Serialize)]
struct SlackUser {
    ok: bool,
    user: SlackUserData,
}

#[derive(Serialize)]
struct SlackUserData {
    name: &'static str,
    profile: SlackProfile,
}

#[derive(Serialize)]
struct SlackProfile {
    display_name: &'static str,
    real_name: &'static str,
}

#[derive(Serialize)]
struct SlackSocketOpen {
    ok: bool,
    url: String,
}

#[derive(Serialize)]
struct SlackSuccess {
    ok: bool,
}

#[derive(serde::Deserialize)]
struct SlackChannelQuery {
    channel: String,
}

#[derive(serde::Deserialize)]
struct SlackUserQuery {
    user: String,
}

#[derive(Serialize)]
struct DiscordHello {
    op: u8,
    d: DiscordHelloData,
}

#[derive(Serialize)]
struct DiscordHelloData {
    heartbeat_interval: u64,
}

#[derive(Serialize)]
struct DiscordReady {
    op: u8,
    s: u8,
    t: &'static str,
    d: DiscordReadyData,
}

#[derive(Serialize)]
struct DiscordReadyData {
    user: DiscordUserId,
}

#[derive(Serialize)]
struct DiscordUserId {
    id: &'static str,
}

#[derive(Serialize)]
struct DiscordMessageCreate {
    op: u8,
    s: u8,
    t: &'static str,
    d: DiscordMessageData,
}

#[derive(Serialize)]
struct DiscordMessageData {
    channel_id: &'static str,
    content: &'static str,
    author: DiscordAuthor,
}

#[derive(Serialize)]
struct DiscordAuthor {
    id: &'static str,
    username: &'static str,
}

#[derive(Serialize)]
struct SlackEventEnvelope {
    envelope_id: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    payload: SlackEventPayload,
}

#[derive(Serialize)]
struct SlackEventPayload {
    event: SlackMessageEvent,
}

#[derive(Serialize)]
struct SlackMessageEvent {
    #[serde(rename = "type")]
    kind: &'static str,
    channel: &'static str,
    user: &'static str,
    text: &'static str,
}

fn json_message(value: &impl Serialize) -> Message {
    Message::Text(
        serde_json::to_string(value)
            .expect("oracle response serializes")
            .into(),
    )
}

#[derive(Clone, Copy)]
pub enum Provider {
    Discord,
    Slack,
}

#[derive(Debug)]
pub enum OracleEvent {
    DiscordIdentify(DiscordIdentify),
    DiscordPost {
        authorization: String,
        body: DiscordPost,
    },
    SlackAck(SlackAck),
    SlackPost {
        authorization: String,
        body: SlackPost,
    },
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct DiscordIdentify {
    op: u8,
    d: DiscordIdentifyData,
}

#[derive(Debug, serde::Deserialize)]
struct DiscordIdentifyData {
    token: String,
    intents: u64,
    properties: DiscordIdentifyProperties,
}

#[derive(Debug, serde::Deserialize)]
struct DiscordIdentifyProperties {
    os: String,
    browser: String,
    device: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct DiscordPost {
    content: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct SlackAck {
    envelope_id: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct SlackPost {
    channel: String,
    text: String,
}

#[derive(Clone)]
struct OracleState {
    provider: Provider,
    websocket_url: String,
    events: tokio::sync::mpsc::UnboundedSender<OracleEvent>,
}

pub struct Oracle {
    pub api_base: String,
    pub events: tokio::sync::mpsc::UnboundedReceiver<OracleEvent>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Oracle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn start(provider: Provider) -> Oracle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind bridge oracle");
    let address = listener.local_addr().expect("oracle address");
    let (events_tx, events) = tokio::sync::mpsc::unbounded_channel();
    let state = OracleState {
        provider,
        websocket_url: format!("ws://{address}/socket"),
        events: events_tx,
    };
    let router = Router::new()
        .route("/channels/{id}", get(discord_channel))
        .route("/channels/{id}/messages", post(discord_post))
        .route("/gateway", get(discord_gateway))
        .route("/conversations.info", get(slack_channel))
        .route("/users.info", get(slack_user))
        .route("/apps.connections.open", post(slack_open))
        .route("/chat.postMessage", post(slack_post))
        .route("/socket", get(websocket))
        .route("/socket/", get(websocket))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("bridge oracle server");
    });
    Oracle {
        api_base: format!("http://{address}"),
        events,
        task,
    }
}

pub async fn verify_round_trip(
    provider: Provider,
    handle: super::NetworkHandle,
    mut driver_events: tokio::sync::broadcast::Receiver<super::DriverEvent>,
    session: tokio::task::JoinHandle<super::SessionOutcome>,
    oracle: &mut Oracle,
) {
    if matches!(provider, Provider::Discord) {
        let identify = recv_oracle(oracle, "IDENTIFY").await;
        let OracleEvent::DiscordIdentify(identify) = identify else {
            panic!("first oracle event was not Discord IDENTIFY: {identify:?}");
        };
        assert_eq!(identify.op, 2);
        assert_eq!(identify.d.token, "discord-token");
        assert_eq!(identify.d.intents, (1 << 0) | (1 << 9) | (1 << 15));
        assert_eq!(identify.d.properties.os, "linux");
        assert_eq!(identify.d.properties.browser, "e6irc");
        assert_eq!(identify.d.properties.device, "e6irc");
    }

    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), driver_events.recv())
            .await
            .expect("connected timeout")
            .expect("connected event"),
        super::DriverEvent::Status {
            status: super::DriverConnectionStatus::Connected,
            revision: 1,
        }
    );
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(2), driver_events.recv())
            .await
            .expect("component-log timeout")
            .expect("component-log event"),
        super::DriverEvent::Line(line) if line == ":*bnc* NOTICE * :component connected: unregistered network"
    ));

    if matches!(provider, Provider::Slack) {
        let ack = recv_oracle(oracle, "ACK").await;
        let OracleEvent::SlackAck(ack) = ack else {
            panic!("first oracle event was not a Slack ACK: {ack:?}");
        };
        assert_eq!(ack.envelope_id, "env-1");
    }

    let expected_line = match provider {
        Provider::Discord => {
            ":alice!alice@discord PRIVMSG #general :hello from Discord".to_string()
        }
        Provider::Slack => ":Alice!Alice@slack PRIVMSG #general :hello from Slack".to_string(),
    };
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), driver_events.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound event"),
        super::DriverEvent::Line(expected_line)
    );

    assert_eq!(
        handle.send("PRIVMSG #general :hello from IRC"),
        super::SendOutcome::Sent
    );
    match (provider, recv_oracle(oracle, "REST post").await) {
        (
            Provider::Discord,
            OracleEvent::DiscordPost {
                authorization,
                body,
            },
        ) => {
            assert_eq!(authorization, "Bot discord-token");
            assert_eq!(body.content, "hello from IRC");
        }
        (
            Provider::Slack,
            OracleEvent::SlackPost {
                authorization,
                body,
            },
        ) => {
            assert_eq!(authorization, "Bearer xoxb-token");
            assert_eq!(body.channel, "C1");
            assert_eq!(body.text, "hello from IRC");
        }
        (_, event) => panic!("wrong provider REST event: {event:?}"),
    }

    handle.shutdown();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(2), session)
            .await
            .expect("session shutdown timeout")
            .expect("session task"),
        super::SessionOutcome::Stopped
    ));
}

async fn recv_oracle(oracle: &mut Oracle, label: &str) -> OracleEvent {
    tokio::time::timeout(std::time::Duration::from_secs(2), oracle.events.recv())
        .await
        .unwrap_or_else(|_| panic!("{label} timeout"))
        .unwrap_or_else(|| panic!("{label} event channel closed"))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
}

async fn discord_channel(
    State(state): State<OracleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !matches!(state.provider, Provider::Discord)
        || id != "42"
        || bearer(&headers) != Some("Bot discord-token")
    {
        return (StatusCode::UNAUTHORIZED, axum::Json(Empty {})).into_response();
    }
    (
        StatusCode::OK,
        axum::Json(DiscordChannel { name: "general" }),
    )
        .into_response()
}

async fn discord_gateway(State(state): State<OracleState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(DiscordGateway {
            url: state.websocket_url,
        }),
    )
}

async fn discord_post(
    State(state): State<OracleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<DiscordPost>,
) -> impl IntoResponse {
    if !matches!(state.provider, Provider::Discord)
        || id != "42"
        || bearer(&headers) != Some("Bot discord-token")
    {
        return StatusCode::NOT_FOUND;
    }
    state
        .events
        .send(OracleEvent::DiscordPost {
            authorization: bearer(&headers)
                .expect("validated Discord authorization")
                .into(),
            body,
        })
        .expect("discord oracle event receiver");
    StatusCode::NO_CONTENT
}

fn slack_authorized(state: &OracleState, headers: &HeaderMap) -> bool {
    matches!(state.provider, Provider::Slack) && bearer(headers) == Some("Bearer xoxb-token")
}

async fn slack_channel(
    State(state): State<OracleState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<SlackChannelQuery>,
) -> impl IntoResponse {
    if !slack_authorized(&state, &headers) || query.channel != "C1" {
        return axum::Json(SlackError {
            ok: false,
            error: "invalid_auth",
        })
        .into_response();
    }
    axum::Json(SlackChannel {
        ok: true,
        channel: SlackChannelData { name: "general" },
    })
    .into_response()
}

async fn slack_user(
    State(state): State<OracleState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<SlackUserQuery>,
) -> impl IntoResponse {
    if !slack_authorized(&state, &headers) || query.user != "U1" {
        return axum::Json(SlackError {
            ok: false,
            error: "invalid_auth",
        })
        .into_response();
    }
    axum::Json(SlackUser {
        ok: true,
        user: SlackUserData {
            name: "alice",
            profile: SlackProfile {
                display_name: "Alice",
                real_name: "Alice Example",
            },
        },
    })
    .into_response()
}

async fn slack_open(State(state): State<OracleState>, headers: HeaderMap) -> impl IntoResponse {
    if !matches!(state.provider, Provider::Slack) || bearer(&headers) != Some("Bearer xapp-token") {
        return axum::Json(SlackError {
            ok: false,
            error: "invalid_auth",
        })
        .into_response();
    }
    axum::Json(SlackSocketOpen {
        ok: true,
        url: state.websocket_url,
    })
    .into_response()
}

async fn slack_post(
    State(state): State<OracleState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<SlackPost>,
) -> impl IntoResponse {
    if !slack_authorized(&state, &headers) {
        return axum::Json(SlackError {
            ok: false,
            error: "invalid_auth",
        })
        .into_response();
    }
    state
        .events
        .send(OracleEvent::SlackPost {
            authorization: bearer(&headers)
                .expect("validated Slack authorization")
                .into(),
            body,
        })
        .expect("slack oracle event receiver");
    axum::Json(SlackSuccess { ok: true }).into_response()
}

async fn websocket(
    State(state): State<OracleState>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    upgrade.on_upgrade(move |socket| drive_websocket(state, socket))
}

async fn drive_websocket(state: OracleState, mut socket: WebSocket) {
    match state.provider {
        Provider::Discord => {
            socket
                .send(json_message(&DiscordHello {
                    op: 10,
                    d: DiscordHelloData {
                        heartbeat_interval: 60_000,
                    },
                }))
                .await
                .expect("discord HELLO");
            loop {
                let Some(Ok(Message::Text(text))) = socket.recv().await else {
                    return;
                };
                let frame: DiscordIdentify = serde_json::from_str(&text).expect("discord IDENTIFY");
                if frame.op == 2 {
                    state
                        .events
                        .send(OracleEvent::DiscordIdentify(frame))
                        .expect("discord oracle event receiver");
                    break;
                }
            }
            socket
                .send(json_message(&DiscordReady {
                    op: 0,
                    s: 1,
                    t: "READY",
                    d: DiscordReadyData {
                        user: DiscordUserId { id: "bot" },
                    },
                }))
                .await
                .expect("discord READY");
            socket
                .send(json_message(&DiscordMessageCreate {
                    op: 0,
                    s: 2,
                    t: "MESSAGE_CREATE",
                    d: DiscordMessageData {
                        channel_id: "42",
                        content: "hello from Discord",
                        author: DiscordAuthor {
                            id: "user",
                            username: "alice",
                        },
                    },
                }))
                .await
                .expect("discord message");
        }
        Provider::Slack => {
            socket
                .send(json_message(&SlackEventEnvelope {
                    envelope_id: "env-1",
                    kind: "events_api",
                    payload: SlackEventPayload {
                        event: SlackMessageEvent {
                            kind: "message",
                            channel: "C1",
                            user: "U1",
                            text: "hello from Slack",
                        },
                    },
                }))
                .await
                .expect("slack event");
            let Some(Ok(Message::Text(text))) = socket.recv().await else {
                return;
            };
            let ack = serde_json::from_str(&text).expect("slack ACK");
            state
                .events
                .send(OracleEvent::SlackAck(ack))
                .expect("slack oracle event receiver");
        }
    }
    while socket.recv().await.is_some() {}
}
