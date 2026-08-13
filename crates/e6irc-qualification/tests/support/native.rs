use super::*;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use axum::extract::ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};

static ENVIRONMENT: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

struct EnvironmentGuard(Vec<(&'static str, Option<OsString>)>);

impl EnvironmentGuard {
    fn set(values: &[(&'static str, &str)]) -> Self {
        let mut previous = Vec::with_capacity(values.len());
        unsafe {
            for (name, value) in values {
                previous.push((*name, std::env::var_os(name)));
                std::env::set_var(name, value);
            }
        }
        Self(previous)
    }
}

impl Drop for EnvironmentGuard {
    fn drop(&mut self) {
        unsafe {
            for (name, value) in self.0.drain(..).rev() {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

#[derive(Clone)]
struct DiscordOracle {
    websocket: String,
    deletes: Arc<AtomicUsize>,
}

async fn start_discord_oracle() -> DiscordOracle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oracle");
    let websocket = format!("ws://{}/socket", listener.local_addr().expect("address"));
    let state = DiscordOracle {
        websocket,
        deletes: Arc::new(AtomicUsize::new(0)),
    };
    let router = Router::new()
        .route("/channels/{id}", get(discord_channel))
        .route("/channels/{id}/messages", post(discord_post))
        .route(
            "/channels/{id}/messages/{message}",
            get(discord_message).delete(discord_delete),
        )
        .route("/gateway", get(discord_gateway))
        .route("/socket", get(discord_socket))
        .route("/socket/", get(discord_socket))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.expect("serve oracle") });
    state
}

fn discord_authorized(headers: &HeaderMap) -> bool {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some("Bot token")
}

async fn discord_channel(
    State(_): State<DiscordOracle>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if id == "42" && discord_authorized(&headers) {
        (StatusCode::OK, Json(serde_json::json!({"name":"general"})))
    } else {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})))
    }
}

async fn discord_gateway(State(state): State<DiscordOracle>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"url":state.websocket}))
}

async fn discord_post(
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if id == "42" && discord_authorized(&headers) && body.get("content").is_some() {
        (StatusCode::OK, Json(serde_json::json!({"id":"m1"})))
    } else {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})))
    }
}

async fn discord_message(
    Path((_id, message)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if message == "m1" && discord_authorized(&headers) {
        (StatusCode::OK, Json(serde_json::json!({"id":"m1"})))
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({})))
    }
}

async fn discord_delete(
    State(state): State<DiscordOracle>,
    Path((_id, message)): Path<(String, String)>,
    headers: HeaderMap,
) -> StatusCode {
    if message == "m1" && discord_authorized(&headers) {
        state.deletes.fetch_add(1, Ordering::SeqCst);
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn discord_socket(websocket: WebSocketUpgrade) -> impl IntoResponse {
    websocket.on_upgrade(|socket| async move { discord_session(socket).await })
}

async fn discord_session(mut socket: WebSocket) {
    socket
        .send(AxumMessage::Text("{\"op\":10,\"d\":{}}".into()))
        .await
        .expect("hello");
    let Some(Ok(AxumMessage::Text(identify))) = socket.next().await else {
        return;
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&identify)
            .ok()
            .and_then(|json| json.get("op").and_then(serde_json::Value::as_i64)),
        Some(2)
    );
    socket
        .send(AxumMessage::Text("{\"t\":\"READY\"}".into()))
        .await
        .expect("ready");
}

#[derive(Clone)]
struct SlackOracle {
    websocket: String,
    posts: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
    deletes: Arc<AtomicUsize>,
}

async fn start_slack_oracle() -> SlackOracle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oracle");
    let state = SlackOracle {
        websocket: format!("ws://{}/socket", listener.local_addr().expect("address")),
        posts: Arc::new(AtomicUsize::new(0)),
        reads: Arc::new(AtomicUsize::new(0)),
        deletes: Arc::new(AtomicUsize::new(0)),
    };
    let router = Router::new()
        .route("/auth.test", post(slack_auth))
        .route("/apps.connections.open", post(slack_open))
        .route("/chat.postMessage", post(slack_post))
        .route("/conversations.replies", get(slack_replies))
        .route("/chat.delete", post(slack_delete))
        .route("/socket", get(slack_socket))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.expect("serve oracle") });
    state
}

fn slack_authorized(headers: &HeaderMap, token: &str) -> bool {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    authorization == Some(token)
}

async fn slack_auth(headers: HeaderMap) -> impl IntoResponse {
    if slack_authorized(&headers, "bot") {
        (StatusCode::OK, Json(serde_json::json!({"ok":true})))
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false})),
        )
    }
}

async fn slack_open(State(state): State<SlackOracle>, headers: HeaderMap) -> impl IntoResponse {
    if slack_authorized(&headers, "app") {
        (
            StatusCode::OK,
            Json(serde_json::json!({"ok":true,"url":state.websocket})),
        )
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false})),
        )
    }
}

async fn slack_post(
    State(state): State<SlackOracle>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if slack_authorized(&headers, "bot")
        && body.get("channel").and_then(serde_json::Value::as_str) == Some("C42")
        && body
            .get("text")
            .and_then(serde_json::Value::as_str)
            .is_some()
    {
        state.posts.fetch_add(1, Ordering::SeqCst);
        (
            StatusCode::OK,
            Json(serde_json::json!({"ok":true,"ts":"1"})),
        )
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false})),
        )
    }
}

async fn slack_replies(
    State(state): State<SlackOracle>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> impl IntoResponse {
    if slack_authorized(&headers, "bot")
        && query.get("channel").is_some_and(|channel| channel == "C42")
        && query.get("ts").is_some_and(|timestamp| timestamp == "1")
    {
        state.reads.fetch_add(1, Ordering::SeqCst);
        (
            StatusCode::OK,
            Json(serde_json::json!({"ok":true,"messages":[{"ts":"1"}]})),
        )
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false})),
        )
    }
}

async fn slack_delete(
    State(state): State<SlackOracle>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if slack_authorized(&headers, "bot")
        && body.get("channel").and_then(serde_json::Value::as_str) == Some("C42")
        && body.get("ts").and_then(serde_json::Value::as_str) == Some("1")
    {
        state.deletes.fetch_add(1, Ordering::SeqCst);
        (StatusCode::OK, Json(serde_json::json!({"ok":true})))
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"ok":false})),
        )
    }
}

async fn slack_socket(websocket: WebSocketUpgrade) -> impl IntoResponse {
    websocket.on_upgrade(|mut socket| async move { while socket.recv().await.is_some() {} })
}

#[derive(Clone)]
struct OidcOracle {
    issuer: String,
    token_endpoint: String,
    introspection_endpoint: String,
    revocation_endpoint: String,
    tokens: Arc<AtomicUsize>,
    introspections: Arc<AtomicUsize>,
    revocations: Arc<AtomicUsize>,
}

async fn start_oidc_oracle() -> OidcOracle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oracle");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    let state = OidcOracle {
        issuer: format!("{base}/issuer"),
        token_endpoint: format!("{base}/token"),
        introspection_endpoint: format!("{base}/introspect"),
        revocation_endpoint: format!("{base}/revoke"),
        tokens: Arc::new(AtomicUsize::new(0)),
        introspections: Arc::new(AtomicUsize::new(0)),
        revocations: Arc::new(AtomicUsize::new(0)),
    };
    let router = Router::new()
        .route(
            "/issuer/.well-known/openid-configuration",
            get(oidc_discovery),
        )
        .route("/token", post(oidc_token_response))
        .route("/introspect", post(oidc_introspect))
        .route("/revoke", post(oidc_revoke))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.expect("serve oracle") });
    state
}

fn oidc_authorized(headers: &HeaderMap) -> bool {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some("Basic Y2xpZW50OnNlY3JldA==")
}

async fn oidc_discovery(State(state): State<OidcOracle>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer":state.issuer,
        "token_endpoint":state.token_endpoint,
        "introspection_endpoint":state.introspection_endpoint,
        "revocation_endpoint":state.revocation_endpoint,
    }))
}

async fn oidc_token_response(
    State(state): State<OidcOracle>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> impl IntoResponse {
    if oidc_authorized(&headers)
        && form
            .get("grant_type")
            .is_some_and(|grant_type| grant_type == "client_credentials")
    {
        state.tokens.fetch_add(1, Ordering::SeqCst);
        (
            StatusCode::OK,
            Json(serde_json::json!({"access_token":"opaque"})),
        )
    } else {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})))
    }
}

async fn oidc_introspect(
    State(state): State<OidcOracle>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> impl IntoResponse {
    if oidc_authorized(&headers) && form.get("token").is_some_and(|token| token == "opaque") {
        state.introspections.fetch_add(1, Ordering::SeqCst);
        (StatusCode::OK, Json(serde_json::json!({"active":true})))
    } else {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})))
    }
}

async fn oidc_revoke(
    State(state): State<OidcOracle>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> StatusCode {
    if oidc_authorized(&headers) && form.get("token").is_some_and(|token| token == "opaque") {
        state.revocations.fetch_add(1, Ordering::SeqCst);
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    }
}

#[test]
fn endpoint_urls_cannot_carry_credentials_or_tokens() {
    assert!(safe_url("https://issuer.example/api").is_some());
    assert!(safe_url("http://127.0.0.1/api").is_some());
    assert!(safe_url("http://[::1]/api").is_some());
    assert!(safe_url("http://issuer.example/api").is_none());
    assert!(safe_url("https://user:secret@issuer.example/api").is_none());
    assert!(safe_url("https://issuer.example/api?token=secret").is_none());
    assert!(safe_url("https://issuer.example/api#secret").is_none());
}

#[test]
fn provider_socket_urls_require_secure_or_loopback_transport() {
    assert!(CampaignSocketUrl::parse("wss://gateway.example/socket").is_some());
    assert!(CampaignSocketUrl::parse("wss://gateway.example/socket?ticket=secret").is_some());
    assert!(CampaignSocketUrl::parse("ws://127.0.0.1/socket").is_some());
    assert!(CampaignSocketUrl::parse("ws://gateway.example/socket").is_none());
    assert!(CampaignSocketUrl::parse("wss://user:secret@gateway.example/socket").is_none());
    assert!(CampaignSocketUrl::parse("wss://gateway.example/socket#fragment").is_none());
}

#[test]
fn oidc_metadata_endpoints_cannot_cross_the_loopback_boundary() {
    let external = safe_url("https://issuer.example").expect("issuer");
    let loopback = safe_url("http://127.0.0.1/issuer").expect("issuer");
    assert!(oidc_endpoint(&external, "https://tokens.example/token").is_some());
    assert!(oidc_endpoint(&external, "http://127.0.0.1/token").is_none());
    assert!(oidc_endpoint(&loopback, "http://127.0.0.1/token").is_some());
    assert!(oidc_endpoint(&loopback, "https://tokens.example/token").is_none());
}

#[test]
fn oidc_discovery_keeps_the_issuer_path() {
    let issuer = safe_url("https://issuer.example/realms/e6").expect("issuer");
    assert_eq!(
        oidc_discovery_url(&issuer).expect("discovery URL").as_str(),
        "https://issuer.example/realms/e6/.well-known/openid-configuration"
    );
}

#[test]
fn oidc_discovery_metadata_must_name_the_requested_issuer() {
    let issuer = safe_url("https://issuer.example/realms/e6").expect("issuer");
    assert!(oidc_issuer_matches(
        &serde_json::json!({"issuer":"https://issuer.example/realms/e6"}),
        &issuer
    ));
    assert!(!oidc_issuer_matches(
        &serde_json::json!({"issuer":"https://other.example/realms/e6"}),
        &issuer
    ));
}

#[test]
fn slack_readback_requires_the_posted_message() {
    assert!(slack_readback_contains(
        &serde_json::json!({"ok":true,"messages":[{"ts":"1"}]}),
        "1"
    ));
    assert!(!slack_readback_contains(
        &serde_json::json!({"ok":true,"messages":[{"ts":"other"}]}),
        "1"
    ));
}

#[tokio::test]
async fn discord_oracle_proves_all_required_phases_and_cleanup() {
    let _environment = ENVIRONMENT
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let oracle = start_discord_oracle().await;
    let base = format!(
        "http://{}/",
        oracle
            .websocket
            .trim_start_matches("ws://")
            .trim_end_matches("/socket")
    );
    let _settings = EnvironmentGuard::set(&[
        ("E6IRC_DISCORD_BOT_TOKEN", "token"),
        ("E6IRC_DISCORD_CHANNEL_ID", "42"),
        ("E6IRC_DISCORD_API_BASE", &base),
    ]);
    assert_eq!(setting("E6IRC_DISCORD_BOT_TOKEN").as_deref(), Some("token"));
    assert_eq!(setting("E6IRC_DISCORD_CHANNEL_ID").as_deref(), Some("42"));
    assert!(safe_url(&setting("E6IRC_DISCORD_API_BASE").expect("base")).is_some());
    let base = safe_url(&setting("E6IRC_DISCORD_API_BASE").expect("base")).expect("safe base");
    let status = client()
        .expect("client")
        .get(
            endpoint(&base, "channels/42")
                .expect("channel endpoint")
                .into_url(),
        )
        .header("Authorization", "Bot token")
        .send()
        .await
        .expect("oracle request")
        .status();
    assert_eq!(status, StatusCode::OK);
    let result = discord("oracle").await;
    assert_eq!(
        result.closed_outcome(TargetKind::Discord),
        super::super::ClosedOutcome::Passed,
        "{result:?}"
    );
    assert_eq!(oracle.deletes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn slack_oracle_proves_all_required_phases_and_cleanup() {
    let _environment = ENVIRONMENT
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let oracle = start_slack_oracle().await;
    let base = format!(
        "http://{}/",
        oracle
            .websocket
            .trim_start_matches("ws://")
            .trim_end_matches("/socket")
    );
    let _settings = EnvironmentGuard::set(&[
        ("E6IRC_SLACK_BOT_TOKEN", "bot"),
        ("E6IRC_SLACK_APP_TOKEN", "app"),
        ("E6IRC_SLACK_CHANNEL_ID", "C42"),
        ("E6IRC_SLACK_API_BASE", &base),
    ]);
    let result = slack("oracle").await;
    assert_eq!(
        result.closed_outcome(TargetKind::Slack),
        super::super::ClosedOutcome::Passed,
        "{result:?}"
    );
    assert_eq!(oracle.posts.load(Ordering::SeqCst), 1);
    assert_eq!(oracle.reads.load(Ordering::SeqCst), 1);
    assert_eq!(oracle.deletes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn oidc_oracle_proves_all_required_phases_and_cleanup() {
    let _environment = ENVIRONMENT
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let oracle = start_oidc_oracle().await;
    let _settings = EnvironmentGuard::set(&[
        ("E6IRC_OIDC_CLIENT_ID", "client"),
        ("E6IRC_OIDC_CLIENT_SECRET", "secret"),
    ]);
    let result = oidc(&oracle.issuer).await;
    assert_eq!(
        result.closed_outcome(TargetKind::Oidc),
        super::super::ClosedOutcome::Passed,
        "{result:?}"
    );
    assert_eq!(oracle.tokens.load(Ordering::SeqCst), 2);
    assert_eq!(oracle.introspections.load(Ordering::SeqCst), 1);
    assert_eq!(oracle.revocations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn native_campaigns_reject_secret_bearing_configuration() {
    let _environment = ENVIRONMENT
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let _settings = EnvironmentGuard::set(&[
        ("E6IRC_DISCORD_BOT_TOKEN", "token"),
        ("E6IRC_DISCORD_CHANNEL_ID", "42"),
        (
            "E6IRC_DISCORD_API_BASE",
            "https://oracle.example/?token=secret",
        ),
        ("E6IRC_SLACK_BOT_TOKEN", "bot"),
        ("E6IRC_SLACK_APP_TOKEN", "app"),
        ("E6IRC_SLACK_CHANNEL_ID", "C42"),
        (
            "E6IRC_SLACK_API_BASE",
            "https://oracle.example/?token=secret",
        ),
        ("E6IRC_OIDC_CLIENT_ID", "client"),
        ("E6IRC_OIDC_CLIENT_SECRET", "secret"),
    ]);
    let discord = discord("oracle").await;
    assert_eq!(
        discord.closed_outcome(TargetKind::Discord),
        super::super::ClosedOutcome::Rejected
    );
    assert!(
        discord
            .phase_outcomes()
            .iter()
            .all(|(_, outcome)| *outcome == PhaseOutcome::NotRun)
    );
    assert_eq!(
        slack("oracle").await.closed_outcome(TargetKind::Slack),
        super::super::ClosedOutcome::Rejected
    );
    assert_eq!(
        oidc("https://client:secret@oracle.example")
            .await
            .closed_outcome(TargetKind::Oidc),
        super::super::ClosedOutcome::Rejected
    );
}

#[tokio::test]
async fn native_campaigns_fail_closed_on_unreachable_transport() {
    let _environment = ENVIRONMENT
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve port");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    drop(listener);
    let _settings = EnvironmentGuard::set(&[
        ("E6IRC_DISCORD_BOT_TOKEN", "token"),
        ("E6IRC_DISCORD_CHANNEL_ID", "42"),
        ("E6IRC_DISCORD_API_BASE", &base),
        ("E6IRC_SLACK_BOT_TOKEN", "bot"),
        ("E6IRC_SLACK_APP_TOKEN", "app"),
        ("E6IRC_SLACK_CHANNEL_ID", "C42"),
        ("E6IRC_SLACK_API_BASE", &base),
        ("E6IRC_OIDC_CLIENT_ID", "client"),
        ("E6IRC_OIDC_CLIENT_SECRET", "secret"),
    ]);
    assert_eq!(
        discord("oracle").await.closed_outcome(TargetKind::Discord),
        super::super::ClosedOutcome::Failed
    );
    assert_eq!(
        slack("oracle").await.closed_outcome(TargetKind::Slack),
        super::super::ClosedOutcome::Failed
    );
    assert_eq!(
        oidc(&format!("{base}/issuer"))
            .await
            .closed_outcome(TargetKind::Oidc),
        super::super::ClosedOutcome::Failed
    );
}
