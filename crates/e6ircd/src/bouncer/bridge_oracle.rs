//! In-process protocol oracle for the Discord and Slack driver tests.
//!
//! It implements only the provider messages the production sessions consume,
//! but those messages cross real HTTP and WebSocket sockets. Keeping the mock
//! transport here gives both drivers one oracle instead of two drifting piles
//! of ad-hoc server code.

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};

#[derive(Clone, Copy)]
pub enum Provider {
    Discord,
    Slack,
}

#[derive(Debug)]
pub enum OracleEvent {
    DiscordIdentify(serde_json::Value),
    DiscordPost {
        authorization: String,
        body: serde_json::Value,
    },
    SlackAck(serde_json::Value),
    SlackPost {
        authorization: String,
        body: serde_json::Value,
    },
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

/// Assert the transport-independent lifecycle plus each provider's exact
/// authentication, inbound mapping, outbound request, and clean shutdown.
/// Keeping this orchestration here makes the two bridge tests differ only in
/// how they construct their real production session.
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
        assert_eq!(identify["d"]["token"], "discord-token");
        assert_eq!(identify["d"]["intents"], (1 << 0) | (1 << 9) | (1 << 15));
    }

    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), driver_events.recv())
            .await
            .expect("connected timeout")
            .expect("connected event"),
        super::DriverEvent::Connected
    );

    if matches!(provider, Provider::Slack) {
        let ack = recv_oracle(oracle, "ACK").await;
        let OracleEvent::SlackAck(ack) = ack else {
            panic!("first oracle event was not a Slack ACK: {ack:?}");
        };
        assert_eq!(ack["envelope_id"], "env-1");
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
            assert_eq!(body["content"], "hello from IRC");
        }
        (
            Provider::Slack,
            OracleEvent::SlackPost {
                authorization,
                body,
            },
        ) => {
            assert_eq!(authorization, "Bearer xoxb-token");
            assert_eq!(body["channel"], "C1");
            assert_eq!(body["text"], "hello from IRC");
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

fn bearer(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

async fn discord_channel(
    State(state): State<OracleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !matches!(state.provider, Provider::Discord)
        || id != "42"
        || bearer(&headers) != "Bot discord-token"
    {
        return (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({})));
    }
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "name": "general" })),
    )
}

async fn discord_gateway(State(state): State<OracleState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "url": state.websocket_url })),
    )
}

async fn discord_post(
    State(state): State<OracleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> impl IntoResponse {
    if !matches!(state.provider, Provider::Discord) || id != "42" {
        return StatusCode::NOT_FOUND;
    }
    state
        .events
        .send(OracleEvent::DiscordPost {
            authorization: bearer(&headers),
            body,
        })
        .expect("discord oracle event receiver");
    StatusCode::NO_CONTENT
}

/// The Slack oracle's request gate: right provider, right query value, right
/// bot bearer — or the Slack-shaped auth failure.
fn slack_gate(
    state: &OracleState,
    headers: &HeaderMap,
    query: &std::collections::HashMap<String, String>,
    param: &str,
    want: &str,
) -> Option<axum::Json<serde_json::Value>> {
    if !matches!(state.provider, Provider::Slack)
        || query.get(param).map(String::as_str) != Some(want)
        || bearer(headers) != "Bearer xoxb-token"
    {
        return Some(axum::Json(
            serde_json::json!({ "ok": false, "error": "invalid_auth" }),
        ));
    }
    None
}

async fn slack_channel(
    State(state): State<OracleState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(fail) = slack_gate(&state, &headers, &query, "channel", "C1") {
        return fail;
    }
    axum::Json(serde_json::json!({
        "ok": true,
        "channel": { "name": "general" }
    }))
}

async fn slack_user(
    State(state): State<OracleState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(fail) = slack_gate(&state, &headers, &query, "user", "U1") {
        return fail;
    }
    axum::Json(serde_json::json!({
        "ok": true,
        "user": {
            "name": "alice",
            "profile": { "display_name": "Alice", "real_name": "Alice Example" }
        }
    }))
}

async fn slack_open(State(state): State<OracleState>, headers: HeaderMap) -> impl IntoResponse {
    if !matches!(state.provider, Provider::Slack) || bearer(&headers) != "Bearer xapp-token" {
        return axum::Json(serde_json::json!({ "ok": false, "error": "invalid_auth" }));
    }
    axum::Json(serde_json::json!({
        "ok": true,
        "url": state.websocket_url
    }))
}

async fn slack_post(
    State(state): State<OracleState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> impl IntoResponse {
    if !matches!(state.provider, Provider::Slack) {
        return axum::Json(serde_json::json!({ "ok": false, "error": "wrong_provider" }));
    }
    state
        .events
        .send(OracleEvent::SlackPost {
            authorization: bearer(&headers),
            body,
        })
        .expect("slack oracle event receiver");
    axum::Json(serde_json::json!({ "ok": true }))
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
                .send(Message::Text(
                    r#"{"op":10,"d":{"heartbeat_interval":60000}}"#.into(),
                ))
                .await
                .expect("discord HELLO");
            loop {
                let Some(Ok(Message::Text(text))) = socket.recv().await else {
                    return;
                };
                let frame: serde_json::Value =
                    serde_json::from_str(&text).expect("discord client frame");
                if frame["op"] == 2 {
                    state
                        .events
                        .send(OracleEvent::DiscordIdentify(frame))
                        .expect("discord oracle event receiver");
                    break;
                }
            }
            socket
                .send(Message::Text(
                    r#"{"op":0,"s":1,"t":"READY","d":{"user":{"id":"bot"}}}"#.into(),
                ))
                .await
                .expect("discord READY");
            socket
                .send(Message::Text(
                    r#"{"op":0,"s":2,"t":"MESSAGE_CREATE","d":{"channel_id":"42","content":"hello from Discord","author":{"id":"user","username":"alice"}}}"#.into(),
                ))
                .await
                .expect("discord message");
        }
        Provider::Slack => {
            socket
                .send(Message::Text(
                    r#"{"envelope_id":"env-1","type":"events_api","payload":{"event":{"type":"message","channel":"C1","user":"U1","text":"hello from Slack"}}}"#.into(),
                ))
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
