use super::*;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct Empty {}

#[derive(Serialize)]
struct Channel {
    name: &'static str,
}

#[derive(Serialize)]
struct DiscordCreated {
    id: &'static str,
}

#[derive(Deserialize)]
struct DiscordPostRequest {
    content: String,
}

#[derive(Deserialize)]
struct SlackPostRequest {
    channel: String,
    text: String,
}

#[derive(Deserialize)]
struct SlackDeleteRequest {
    channel: String,
    ts: String,
}

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
    content: Arc<Mutex<Option<String>>>,
    deletes: Arc<AtomicUsize>,
}

async fn start_discord_oracle() -> DiscordOracle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oracle");
    let websocket = format!("ws://{}/socket", listener.local_addr().expect("address"));
    let state = DiscordOracle {
        websocket,
        content: Arc::new(Mutex::new(None)),
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
        (StatusCode::OK, Json(Channel { name: "general" })).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, Json(Empty {})).into_response()
    }
}

async fn discord_gateway(State(state): State<DiscordOracle>) -> Json<DiscordGateway> {
    Json(DiscordGateway {
        url: state.websocket,
    })
}

async fn discord_post(
    State(state): State<DiscordOracle>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DiscordPostRequest>,
) -> impl IntoResponse {
    if id == "42" && discord_authorized(&headers) && !body.content.is_empty() {
        *state.content.lock().expect("content lock") = Some(body.content);
        (StatusCode::OK, Json(DiscordCreated { id: "1" })).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, Json(Empty {})).into_response()
    }
}

async fn discord_message(
    State(state): State<DiscordOracle>,
    Path((_id, message)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if message == "1"
        && discord_authorized(&headers)
        && let Some(content) = state.content.lock().expect("content lock").clone()
    {
        (
            StatusCode::OK,
            Json(DiscordMessage {
                id: DiscordMessageId::parse("1".into()).expect("message ID"),
                content,
            }),
        )
            .into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(Empty {})).into_response()
    }
}

async fn discord_delete(
    State(state): State<DiscordOracle>,
    Path((_id, message)): Path<(String, String)>,
    headers: HeaderMap,
) -> StatusCode {
    if message == "1" && discord_authorized(&headers) {
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
        .send(AxumMessage::Text(
            "{\"op\":10,\"d\":{\"heartbeat_interval\":1000}}".into(),
        ))
        .await
        .expect("hello");
    let Some(Ok(AxumMessage::Text(identify))) = socket.next().await else {
        return;
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&identify)
            .ok()
            .and_then(|frame| frame.get("op").and_then(serde_json::Value::as_u64)),
        Some(2)
    );
    socket
        .send(AxumMessage::Text("{\"op\":1}".into()))
        .await
        .expect("heartbeat request");
    let Some(Ok(AxumMessage::Text(heartbeat))) = socket.next().await else {
        return;
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&heartbeat)
            .ok()
            .and_then(|frame| frame.get("op").and_then(serde_json::Value::as_u64)),
        Some(1)
    );
    socket
        .send(AxumMessage::Text("{\"op\":0,\"t\":\"READY\"}".into()))
        .await
        .expect("ready");
}

#[derive(Clone)]
struct SlackOracle {
    websocket: String,
    sends_hello: bool,
    opens: Arc<AtomicUsize>,
    posts: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
    deletes: Arc<AtomicUsize>,
}

async fn start_slack_oracle() -> SlackOracle {
    start_slack_oracle_with_hello(true).await
}

async fn start_slack_oracle_with_hello(sends_hello: bool) -> SlackOracle {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind oracle");
    let state = SlackOracle {
        websocket: format!("ws://{}/socket", listener.local_addr().expect("address")),
        sends_hello,
        opens: Arc::new(AtomicUsize::new(0)),
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
        (StatusCode::OK, Json(SlackResult { ok: true })).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, Json(SlackResult { ok: false })).into_response()
    }
}

async fn slack_open(State(state): State<SlackOracle>, headers: HeaderMap) -> impl IntoResponse {
    if slack_authorized(&headers, "app") {
        state.opens.fetch_add(1, Ordering::SeqCst);
        (
            StatusCode::OK,
            Json(SlackSocketOpen {
                ok: true,
                url: Some(state.websocket),
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(SlackSocketOpen {
                ok: false,
                url: None,
            }),
        )
            .into_response()
    }
}

async fn slack_post(
    State(state): State<SlackOracle>,
    headers: HeaderMap,
    Json(body): Json<SlackPostRequest>,
) -> impl IntoResponse {
    if slack_authorized(&headers, "bot") && body.channel == "C42" && !body.text.is_empty() {
        state.posts.fetch_add(1, Ordering::SeqCst);
        (
            StatusCode::OK,
            Json(SlackMessagePost {
                ok: true,
                ts: Some(SlackTimestamp::parse("1.0".into()).expect("timestamp")),
                message: None,
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(SlackMessagePost {
                ok: false,
                ts: None,
                message: None,
            }),
        )
            .into_response()
    }
}

async fn slack_replies(
    State(state): State<SlackOracle>,
    headers: HeaderMap,
    Query(query): Query<BTreeMap<String, String>>,
) -> impl IntoResponse {
    if slack_authorized(&headers, "bot")
        && query.get("channel").is_some_and(|channel| channel == "C42")
        && query.get("ts").is_some_and(|timestamp| timestamp == "1.0")
    {
        state.reads.fetch_add(1, Ordering::SeqCst);
        (
            StatusCode::OK,
            Json(SlackReplies {
                ok: true,
                messages: vec![SlackReply {
                    ts: SlackTimestamp::parse("1.0".into()).expect("timestamp"),
                }],
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(SlackReplies {
                ok: false,
                messages: Vec::new(),
            }),
        )
            .into_response()
    }
}

async fn slack_delete(
    State(state): State<SlackOracle>,
    headers: HeaderMap,
    Json(body): Json<SlackDeleteRequest>,
) -> impl IntoResponse {
    if slack_authorized(&headers, "bot") && body.channel == "C42" && body.ts == "1.0" {
        state.deletes.fetch_add(1, Ordering::SeqCst);
        (StatusCode::OK, Json(SlackResult { ok: true })).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, Json(SlackResult { ok: false })).into_response()
    }
}

async fn slack_socket(
    State(state): State<SlackOracle>,
    websocket: WebSocketUpgrade,
) -> impl IntoResponse {
    websocket.on_upgrade(move |mut socket| async move {
        if !state.sends_hello {
            return;
        }
        socket
            .send(AxumMessage::Text(
                serde_json::to_string(&SlackHello {
                    kind: SlackSocketFrame::Hello,
                })
                .expect("Slack hello serializes")
                .into(),
            ))
            .await
            .expect("send hello");
        while socket.recv().await.is_some() {}
    })
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
    revoked: Arc<AtomicBool>,
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
        revoked: Arc::new(AtomicBool::new(false)),
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

async fn oidc_discovery(State(state): State<OidcOracle>) -> Json<OidcDiscovery> {
    Json(OidcDiscovery {
        issuer: state.issuer,
        token_endpoint: state.token_endpoint,
        introspection_endpoint: state.introspection_endpoint,
        revocation_endpoint: state.revocation_endpoint,
    })
}

async fn oidc_token_response(
    State(state): State<OidcOracle>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> axum::response::Response {
    if oidc_authorized(&headers)
        && form
            .get("grant_type")
            .is_some_and(|grant_type| grant_type == "client_credentials")
    {
        state.tokens.fetch_add(1, Ordering::SeqCst);
        (
            StatusCode::OK,
            Json(OidcToken {
                access_token: "opaque".into(),
            }),
        )
            .into_response()
    } else {
        (StatusCode::UNAUTHORIZED, Json(Empty {})).into_response()
    }
}

async fn oidc_introspect(
    State(state): State<OidcOracle>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> axum::response::Response {
    if oidc_authorized(&headers) && form.get("token").is_some_and(|token| token == "opaque") {
        state.introspections.fetch_add(1, Ordering::SeqCst);
        (
            StatusCode::OK,
            Json(OidcIntrospection {
                active: !state.revoked.load(Ordering::SeqCst),
            }),
        )
            .into_response()
    } else {
        (StatusCode::UNAUTHORIZED, Json(Empty {})).into_response()
    }
}

async fn oidc_revoke(
    State(state): State<OidcOracle>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> StatusCode {
    if oidc_authorized(&headers) && form.get("token").is_some_and(|token| token == "opaque") {
        state.revocations.fetch_add(1, Ordering::SeqCst);
        state.revoked.store(true, Ordering::SeqCst);
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
    assert!(safe_url("https://10.0.0.1/api").is_none());
    assert!(safe_url("https://[fd00::1]/api").is_none());
}

#[test]
fn provider_socket_urls_require_secure_or_loopback_transport() {
    assert!(CampaignSocketUrl::parse("wss://gateway.example/socket").is_some());
    assert!(CampaignSocketUrl::parse("wss://gateway.example/socket?ticket=secret").is_some());
    assert!(CampaignSocketUrl::parse("ws://127.0.0.1/socket").is_some());
    assert!(CampaignSocketUrl::parse("ws://gateway.example/socket").is_none());
    assert!(CampaignSocketUrl::parse("wss://user:secret@gateway.example/socket").is_none());
    assert!(CampaignSocketUrl::parse("wss://gateway.example/socket#fragment").is_none());
    assert!(CampaignSocketUrl::parse("wss://10.0.0.1/socket").is_none());
}

#[test]
fn provider_identifiers_have_distinct_closed_syntaxes() {
    assert!(Secret::parse("credential".into()).is_some());
    assert!(Secret::parse("credential\nvalue".into()).is_none());
    assert!(DiscordChannelId::parse("42".into()).is_some());
    assert!(DiscordChannelId::parse("C42".into()).is_none());
    assert!(SlackChannelId::parse("C42".into()).is_some());
    assert!(SlackChannelId::parse("42".into()).is_none());
    assert!(DiscordMessageId::parse("../../gateway".into()).is_none());
    assert!(SlackTimestamp::parse("1?token=secret".into()).is_none());
}

#[test]
fn oidc_metadata_endpoints_cannot_cross_the_loopback_boundary() {
    let external = safe_url("https://issuer.example").expect("issuer");
    let loopback = safe_url("http://127.0.0.1/issuer").expect("issuer");
    assert!(oidc_endpoint(&external, "https://tokens.example/token").is_some());
    assert!(oidc_endpoint(&external, "http://127.0.0.1/token").is_none());
    assert!(oidc_endpoint(&loopback, "http://127.0.0.1/token").is_some());
    assert!(oidc_endpoint(&loopback, "https://tokens.example/token").is_none());
    assert!(oidc_endpoint(&external, "https://10.0.0.1/token").is_none());
}

#[test]
fn provider_sockets_stay_in_their_endpoint_scope() {
    let external = safe_url("https://provider.example").expect("provider");
    let loopback = safe_url("http://127.0.0.1/provider").expect("provider");
    assert!(
        CampaignSocketUrl::parse("wss://gateway.example/socket")
            .is_some_and(|url| url.has_scope(external.scope))
    );
    assert!(
        !CampaignSocketUrl::parse("ws://127.0.0.1/socket")
            .is_some_and(|url| url.has_scope(external.scope))
    );
    assert!(
        CampaignSocketUrl::parse("ws://127.0.0.1/socket")
            .is_some_and(|url| url.has_scope(loopback.scope))
    );
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
        &OidcDiscovery {
            issuer: "https://issuer.example/realms/e6".into(),
            token_endpoint: "https://issuer.example/token".into(),
            introspection_endpoint: "https://issuer.example/introspect".into(),
            revocation_endpoint: "https://issuer.example/revoke".into(),
        },
        &issuer
    ));
    assert!(!oidc_issuer_matches(
        &OidcDiscovery {
            issuer: "https://other.example/realms/e6".into(),
            token_endpoint: "https://issuer.example/token".into(),
            introspection_endpoint: "https://issuer.example/introspect".into(),
            revocation_endpoint: "https://issuer.example/revoke".into(),
        },
        &issuer
    ));
}

#[test]
fn slack_readback_requires_the_posted_message() {
    assert!(slack_readback_contains(
        &SlackReplies {
            ok: true,
            messages: vec![SlackReply {
                ts: SlackTimestamp::parse("1.0".into()).expect("timestamp")
            }],
        },
        &SlackTimestamp::parse("1.0".into()).expect("timestamp")
    ));
    assert!(!slack_readback_contains(
        &SlackReplies {
            ok: true,
            messages: vec![SlackReply {
                ts: SlackTimestamp::parse("2.0".into()).expect("timestamp")
            }],
        },
        &SlackTimestamp::parse("1.0".into()).expect("timestamp")
    ));
}

#[test]
fn discord_readback_requires_the_posted_message() {
    assert!(discord_readback_matches(
        &DiscordMessage {
            id: DiscordMessageId::parse("1".into()).expect("message ID"),
            content: "marker".into(),
        },
        &DiscordMessageId::parse("1".into()).expect("message ID"),
        "marker"
    ));
    assert!(!discord_readback_matches(
        &DiscordMessage {
            id: DiscordMessageId::parse("2".into()).expect("message ID"),
            content: "marker".into(),
        },
        &DiscordMessageId::parse("1".into()).expect("message ID"),
        "marker"
    ));
    assert!(!discord_readback_matches(
        &DiscordMessage {
            id: DiscordMessageId::parse("1".into()).expect("message ID"),
            content: "other".into(),
        },
        &DiscordMessageId::parse("1".into()).expect("message ID"),
        "marker"
    ));
}

#[test]
fn provider_contracts_reject_missing_or_mistyped_required_fields() {
    assert!(serde_json::from_str::<DiscordGateway>(r#"{}"#).is_err());
    assert!(serde_json::from_str::<DiscordMessage>(r#"{"id":"m1"}"#).is_err());
    assert!(serde_json::from_str::<SlackReplies>(r#"{"ok":true}"#).is_err());
    assert!(
        serde_json::from_str::<OidcDiscovery>(r#"{"issuer":"https://issuer.example"}"#).is_err()
    );
    assert!(serde_json::from_str::<OidcIntrospection>(r#"{"active":"yes"}"#).is_err());
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
    assert_eq!(
        Secret::setting("E6IRC_DISCORD_BOT_TOKEN")
            .map(|value| value.as_str().to_string())
            .as_deref(),
        Some("token")
    );
    assert_eq!(
        environment_value("E6IRC_DISCORD_CHANNEL_ID").as_deref(),
        Some("42")
    );
    assert!(safe_url(&environment_value("E6IRC_DISCORD_API_BASE").expect("base")).is_some());
    let base =
        safe_url(&environment_value("E6IRC_DISCORD_API_BASE").expect("base")).expect("safe base");
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
    assert_eq!(oracle.opens.load(Ordering::SeqCst), 2);
    assert_eq!(oracle.posts.load(Ordering::SeqCst), 1);
    assert_eq!(oracle.reads.load(Ordering::SeqCst), 1);
    assert_eq!(oracle.deletes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn slack_connection_requires_the_hello_frame() {
    let oracle = start_slack_oracle_with_hello(false).await;
    let base = format!(
        "http://{}/",
        oracle
            .websocket
            .trim_start_matches("ws://")
            .trim_end_matches("/socket")
    );
    let base = safe_url(&base).expect("safe base");
    assert_eq!(
        slack_connect(
            &client().expect("client"),
            &base,
            &Secret::parse("app".into()).expect("app token")
        )
        .await,
        PhaseOutcome::Failed
    );
}

#[test]
fn slack_hello_has_a_closed_shape() {
    assert!(slack_hello(r#"{"type":"hello"}"#));
    assert!(!slack_hello(r#"{"type":"disconnect"}"#));
    assert!(!slack_hello(r#"{"type":1}"#));
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
    assert_eq!(oracle.introspections.load(Ordering::SeqCst), 2);
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
