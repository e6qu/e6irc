//! In-process Discord and Slack protocol oracle.
//!
//! Two ways to drive it. The scripted round trip ([`start`] and
//! [`verify_round_trip`]) plays one fixed conversation per provider. The
//! manual mode ([`Options::manual`]) hands the socket to the test: every
//! connection is announced as [`OracleEvent::Connected`], every frame the
//! driver sends arrives as [`OracleEvent::ClientFrame`], and the test writes
//! frames (or a close code) with [`Oracle::send`] / [`Oracle::close`] — so a
//! test states the exact gateway conversation it proves instead of the oracle
//! growing one hard-coded script per case.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde_json::json;

#[derive(Clone, Copy)]
pub enum Provider {
    Discord,
    Slack,
}

/// How the oracle behaves beyond the happy path.
#[derive(Clone, Default)]
pub struct Options {
    /// The test drives every WebSocket frame (see the module docs).
    pub manual: bool,
    /// How long a message post (Discord `POST /channels/{id}/messages`, Slack
    /// `chat.postMessage`) takes to answer.
    pub post_delay: Duration,
    /// The first message post is answered `429` with a one-second
    /// `Retry-After` (and Discord's `retry_after` body); later ones succeed.
    pub rate_limit_first_post: bool,
    /// The first Slack `users.info` fails; later ones succeed.
    pub fail_first_user_lookup: bool,
}

#[derive(Debug)]
pub enum OracleEvent {
    DiscordIdentify(DiscordIdentify),
    DiscordPost {
        authorization: String,
        body: serde_json::Value,
    },
    SlackAck(SlackAck),
    SlackPost {
        authorization: String,
        body: serde_json::Value,
    },
    /// Manual mode: WebSocket connection number `n` (from 0) was accepted.
    Connected(usize),
    /// Manual mode: connection `n` sent this text frame.
    ClientFrame(usize, String),
    /// Manual mode: connection `n` sent a WebSocket Ping.
    Ping(usize),
    /// A Slack `users.info` lookup for this user id.
    UserLookup(String),
    /// A message post was answered `429`.
    RateLimited,
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
pub(super) struct SlackAck {
    pub(super) envelope_id: String,
}

#[derive(serde::Deserialize)]
struct SlackChannelQuery {
    channel: String,
}

#[derive(serde::Deserialize)]
struct SlackUserQuery {
    user: String,
}

#[derive(Clone)]
struct OracleState {
    provider: Provider,
    options: Options,
    websocket_url: String,
    events: tokio::sync::mpsc::UnboundedSender<OracleEvent>,
    connections: Arc<AtomicUsize>,
    /// Manual mode: the writer for each accepted connection, by number.
    writers: Arc<Mutex<Vec<tokio::sync::mpsc::UnboundedSender<Message>>>>,
    posts_rate_limited: Arc<AtomicBool>,
    user_lookup_failed: Arc<AtomicBool>,
}

pub struct Oracle {
    pub api_base: String,
    pub websocket_url: String,
    pub events: tokio::sync::mpsc::UnboundedReceiver<OracleEvent>,
    writers: Arc<Mutex<Vec<tokio::sync::mpsc::UnboundedSender<Message>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Oracle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Oracle {
    /// Manual mode: write one text frame to connection `connection`.
    pub fn send(&self, connection: usize, frame: serde_json::Value) {
        self.write(connection, Message::Text(frame.to_string().into()));
    }

    /// Manual mode: close connection `connection` with `code`.
    pub fn close(&self, connection: usize, code: u16) {
        self.write(
            connection,
            Message::Close(Some(CloseFrame {
                code,
                reason: "oracle close".into(),
            })),
        );
    }

    fn write(&self, connection: usize, message: Message) {
        let writers = self.writers.lock().expect("oracle writers");
        writers
            .get(connection)
            .unwrap_or_else(|| panic!("no oracle connection {connection}"))
            .send(message)
            .unwrap_or_else(|_| panic!("oracle connection {connection} already ended"));
    }

    /// Manual mode: wait until connection `connection` has been accepted.
    /// Reads the connection registry, not the event stream: the `Connected`
    /// event can already have been skipped by [`Oracle::next_frame`] while a
    /// test waited for a frame on an older socket.
    pub async fn wait_connected(&self, connection: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while self.writers.lock().expect("oracle writers").len() <= connection {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("socket {connection} never connected"));
    }

    /// The next event, or a panic naming `label` after two seconds.
    pub async fn next(&mut self, label: &str) -> OracleEvent {
        recv_oracle(self, label).await
    }

    /// The next frame the driver sent on any connection, skipping heartbeats
    /// and pings the test did not ask about.
    pub async fn next_frame(&mut self, label: &str) -> (usize, serde_json::Value) {
        loop {
            if let OracleEvent::ClientFrame(connection, text) = self.next(label).await {
                let frame: serde_json::Value =
                    serde_json::from_str(&text).expect("driver frames are JSON");
                if frame["op"] == 1 {
                    continue;
                }
                return (connection, frame);
            }
        }
    }
}

pub async fn start(provider: Provider) -> Oracle {
    start_with(provider, Options::default()).await
}

pub async fn start_with(provider: Provider, options: Options) -> Oracle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind bridge oracle");
    let address = listener.local_addr().expect("oracle address");
    let (events_tx, events) = tokio::sync::mpsc::unbounded_channel();
    let writers = Arc::new(Mutex::new(Vec::new()));
    let state = OracleState {
        provider,
        options,
        websocket_url: format!("ws://{address}/socket"),
        events: events_tx,
        connections: Arc::new(AtomicUsize::new(0)),
        writers: writers.clone(),
        posts_rate_limited: Arc::new(AtomicBool::new(false)),
        user_lookup_failed: Arc::new(AtomicBool::new(false)),
    };
    let router = Router::new()
        .route("/users/@me", get(discord_me))
        .route("/channels/{id}", get(discord_channel))
        .route("/channels/{id}/messages", post(discord_post))
        .route("/gateway", get(discord_gateway))
        .route("/auth.test", post(slack_auth_test))
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
        websocket_url: format!("ws://{address}/socket"),
        events,
        writers,
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
        assert_eq!(
            identify.d.intents,
            e6irc_proto::provider::DISCORD_GATEWAY_INTENTS
        );
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
        super::DriverEvent::Line(super::BufferedLine { line, .. }) if line == ":*bnc* NOTICE * :component connected: unregistered network"
    ));

    if matches!(provider, Provider::Slack) {
        let ack = recv_significant(oracle, "ACK").await;
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
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(2), driver_events.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound event"),
        super::DriverEvent::Line(super::BufferedLine { line, .. }) if line == expected_line
    ));

    assert_eq!(
        handle.send("PRIVMSG #general :hello from IRC"),
        super::SendOutcome::Sent
    );
    match (provider, recv_significant(oracle, "REST post").await) {
        (
            Provider::Discord,
            OracleEvent::DiscordPost {
                authorization,
                body,
            },
        ) => {
            assert_eq!(authorization, "Bot discord-token");
            assert_eq!(body["content"], "hello from IRC");
            assert_eq!(body["allowed_mentions"], json!({ "parse": [] }));
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
    // The accepted post is echoed once, under the bot's own name — the line
    // its dropped gateway copy would have been.
    let host = match provider {
        Provider::Discord => "discord",
        Provider::Slack => "slack",
    };
    let echo = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match driver_events.recv().await.expect("driver events") {
                super::DriverEvent::Echo { line, origin } => return (line.line, origin),
                super::DriverEvent::Line(line) => {
                    assert!(
                        !line.line.contains("hello from IRC"),
                        "the post is relayed as an ordinary line: {}",
                        line.line
                    );
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the delivered post was never echoed");
    assert_eq!(echo.1, 0, "sent through the untracked handle");
    assert!(
        echo.0.ends_with(&format!(
            " :{BOT_NAME}!{BOT_NAME}@{host} PRIVMSG #general :hello from IRC"
        )),
        "{}",
        echo.0
    );

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

/// [`recv_oracle`], passing over the name lookups a Slack session makes.
async fn recv_significant(oracle: &mut Oracle, label: &str) -> OracleEvent {
    loop {
        match recv_oracle(oracle, label).await {
            OracleEvent::UserLookup(_) => {}
            event => return event,
        }
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
}

fn discord_ready(websocket_url: &str) -> serde_json::Value {
    json!({
        "op": 0, "s": 1, "t": "READY",
        "d": {
            "user": { "id": "bot" },
            "session_id": "session-1",
            "resume_gateway_url": websocket_url,
        },
    })
}

fn discord_message(sequence: u64, content: &str) -> serde_json::Value {
    json!({
        "op": 0, "s": sequence, "t": "MESSAGE_CREATE",
        "d": {
            "channel_id": "42",
            "content": content,
            "author": { "id": "user", "username": "alice" },
        },
    })
}

/// A READY for the manual Discord tests: `resume_gateway_url` is this oracle.
pub fn discord_ready_frame(oracle: &Oracle) -> serde_json::Value {
    discord_ready(&oracle.websocket_url)
}

/// A MESSAGE_CREATE from `alice` in channel 42.
pub fn discord_message_frame(sequence: u64, content: &str) -> serde_json::Value {
    discord_message(sequence, content)
}

/// A HELLO with `interval_ms` between heartbeats.
pub fn discord_hello_frame(interval_ms: u64) -> serde_json::Value {
    json!({ "op": 10, "d": { "heartbeat_interval": interval_ms } })
}

/// A Slack `events_api` envelope carrying `event`.
pub fn slack_envelope(envelope_id: &str, event: serde_json::Value) -> serde_json::Value {
    json!({ "envelope_id": envelope_id, "type": "events_api", "payload": { "event": event } })
}

/// A plain user message in C1 from U1.
pub fn slack_message(text: &str) -> serde_json::Value {
    json!({ "type": "message", "channel": "C1", "user": "U1", "text": text })
}

/// The bot's own account, under the name its posts are echoed as.
async fn discord_me(State(state): State<OracleState>, headers: HeaderMap) -> impl IntoResponse {
    if !matches!(state.provider, Provider::Discord) || bearer(&headers) != Some("Bot discord-token")
    {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({}))).into_response();
    }
    (
        StatusCode::OK,
        axum::Json(json!({ "id": "bot", "username": BOT_NAME })),
    )
        .into_response()
}

/// The name both providers give the bridge's own account.
pub const BOT_NAME: &str = "e6ircbot";

async fn discord_channel(
    State(state): State<OracleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !matches!(state.provider, Provider::Discord)
        || id != "42"
        || bearer(&headers) != Some("Bot discord-token")
    {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({}))).into_response();
    }
    (StatusCode::OK, axum::Json(json!({ "name": "general" }))).into_response()
}

async fn discord_gateway(State(state): State<OracleState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(json!({ "url": state.websocket_url })),
    )
}

/// Answer the first post `429` when the options ask for it: the one place
/// both providers' rate-limit contract is written.
fn rate_limited(state: &OracleState) -> Option<axum::response::Response> {
    if state.options.rate_limit_first_post && !state.posts_rate_limited.swap(true, Ordering::SeqCst)
    {
        state
            .events
            .send(OracleEvent::RateLimited)
            .expect("oracle event receiver");
        let body = match state.provider {
            Provider::Discord => json!({ "message": "You are being rate limited.",
                                          "retry_after": 1.0, "global": false }),
            Provider::Slack => json!({ "ok": false, "error": "ratelimited" }),
        };
        return Some(
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("Retry-After", "1")],
                axum::Json(body),
            )
                .into_response(),
        );
    }
    None
}

async fn discord_post(
    State(state): State<OracleState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::response::Response {
    if !matches!(state.provider, Provider::Discord)
        || id != "42"
        || bearer(&headers) != Some("Bot discord-token")
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    tokio::time::sleep(state.options.post_delay).await;
    if let Some(limited) = rate_limited(&state) {
        return limited;
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
    StatusCode::NO_CONTENT.into_response()
}

fn slack_authorized(state: &OracleState, headers: &HeaderMap) -> bool {
    matches!(state.provider, Provider::Slack) && bearer(headers) == Some("Bearer xoxb-token")
}

fn slack_refused() -> axum::response::Response {
    axum::Json(json!({ "ok": false, "error": "invalid_auth" })).into_response()
}

async fn slack_auth_test(
    State(state): State<OracleState>,
    headers: HeaderMap,
) -> axum::response::Response {
    if !slack_authorized(&state, &headers) {
        return slack_refused();
    }
    axum::Json(json!({ "ok": true, "user": BOT_NAME, "user_id": "UBOT", "bot_id": "BBOT" }))
        .into_response()
}

async fn slack_channel(
    State(state): State<OracleState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<SlackChannelQuery>,
) -> axum::response::Response {
    if !slack_authorized(&state, &headers) || query.channel != "C1" {
        return slack_refused();
    }
    axum::Json(json!({ "ok": true, "channel": { "name": "general" } })).into_response()
}

async fn slack_user(
    State(state): State<OracleState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<SlackUserQuery>,
) -> axum::response::Response {
    state
        .events
        .send(OracleEvent::UserLookup(query.user.clone()))
        .expect("slack oracle event receiver");
    if !slack_authorized(&state, &headers) {
        return slack_refused();
    }
    if state.options.fail_first_user_lookup
        && !state.user_lookup_failed.swap(true, Ordering::SeqCst)
    {
        return axum::Json(json!({ "ok": false, "error": "fatal_error" })).into_response();
    }
    let (name, display) = match query.user.as_str() {
        "U1" => ("alice", "Alice"),
        "U2" => ("bob", "Bob"),
        _ => return axum::Json(json!({ "ok": false, "error": "user_not_found" })).into_response(),
    };
    axum::Json(json!({
        "ok": true,
        "user": { "name": name, "profile": { "display_name": display, "real_name": display } },
    }))
    .into_response()
}

async fn slack_open(
    State(state): State<OracleState>,
    headers: HeaderMap,
) -> axum::response::Response {
    if !matches!(state.provider, Provider::Slack) || bearer(&headers) != Some("Bearer xapp-token") {
        return slack_refused();
    }
    axum::Json(json!({ "ok": true, "url": state.websocket_url })).into_response()
}

async fn slack_post(
    State(state): State<OracleState>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::response::Response {
    if !slack_authorized(&state, &headers) {
        return slack_refused();
    }
    tokio::time::sleep(state.options.post_delay).await;
    if let Some(limited) = rate_limited(&state) {
        return limited;
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
    axum::Json(json!({ "ok": true })).into_response()
}

async fn websocket(
    State(state): State<OracleState>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    upgrade.on_upgrade(move |socket| drive_websocket(state, socket))
}

async fn drive_websocket(state: OracleState, socket: WebSocket) {
    let connection = state.connections.fetch_add(1, Ordering::SeqCst);
    if state.options.manual {
        drive_manually(state, connection, socket).await;
    } else {
        match state.provider {
            Provider::Discord => discord_round_trip(state, socket).await,
            Provider::Slack => slack_round_trip(state, socket).await,
        }
    }
}

async fn drive_manually(state: OracleState, connection: usize, mut socket: WebSocket) {
    let (writer, mut outgoing) = tokio::sync::mpsc::unbounded_channel();
    {
        let mut writers = state.writers.lock().expect("oracle writers");
        assert_eq!(writers.len(), connection, "connections register in order");
        writers.push(writer);
    }
    state
        .events
        .send(OracleEvent::Connected(connection))
        .expect("oracle event receiver");
    loop {
        tokio::select! {
            frame = outgoing.recv() => {
                let Some(frame) = frame else { return };
                let closing = matches!(frame, Message::Close(_));
                if socket.send(frame).await.is_err() {
                    return;
                }
                if closing {
                    // Finish the close handshake: a socket dropped with the
                    // driver's frames unread is reset, and a reset can reach
                    // the driver before the close code does.
                    drop(
                        tokio::time::timeout(Duration::from_secs(2), async {
                            while socket.recv().await.is_some() {}
                        })
                        .await,
                    );
                    return;
                }
            }
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Text(text))) => {
                    drop(state.events.send(OracleEvent::ClientFrame(connection, text.to_string())));
                }
                Some(Ok(Message::Ping(_))) => {
                    drop(state.events.send(OracleEvent::Ping(connection)));
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return,
            },
        }
    }
}

async fn discord_round_trip(state: OracleState, mut socket: WebSocket) {
    socket
        .send(Message::Text(
            discord_hello_frame(60_000).to_string().into(),
        ))
        .await
        .expect("discord HELLO");
    loop {
        let Some(Ok(Message::Text(text))) = socket.recv().await else {
            return;
        };
        let frame: serde_json::Value = serde_json::from_str(&text).expect("discord frame JSON");
        if frame["op"] == 2 {
            let identify: DiscordIdentify =
                serde_json::from_value(frame).expect("discord IDENTIFY");
            state
                .events
                .send(OracleEvent::DiscordIdentify(identify))
                .expect("discord oracle event receiver");
            break;
        }
    }
    for frame in [
        discord_ready(&state.websocket_url),
        discord_message(2, "hello from Discord"),
    ] {
        socket
            .send(Message::Text(frame.to_string().into()))
            .await
            .expect("discord dispatch");
    }
    while let Some(Ok(message)) = socket.recv().await {
        if let Message::Text(text) = message
            && serde_json::from_str::<serde_json::Value>(&text).is_ok_and(|frame| frame["op"] == 1)
        {
            drop(
                socket
                    .send(Message::Text(json!({ "op": 11 }).to_string().into()))
                    .await,
            );
        }
    }
}

async fn slack_round_trip(state: OracleState, mut socket: WebSocket) {
    socket
        .send(Message::Text(
            slack_envelope("env-1", slack_message("hello from Slack"))
                .to_string()
                .into(),
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
    while socket.recv().await.is_some() {}
}
