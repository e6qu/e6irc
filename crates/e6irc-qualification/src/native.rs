use std::env;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, StatusCode, Url};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use super::{PhaseOutcome, ProbeReport, SafeText, TargetKind};

const TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn run(kind: TargetKind, target: &str) -> ProbeReport {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(_) => return ProbeReport::uniform(PhaseOutcome::Failed),
    };
    runtime.block_on(async move {
        match kind {
            TargetKind::Discord => discord(target).await,
            TargetKind::Slack => slack(target).await,
            TargetKind::Oidc => oidc(target).await,
            TargetKind::PublicIrc | TargetKind::Scale => ProbeReport::uniform(PhaseOutcome::Failed),
        }
    })
}

fn report(
    authentication: PhaseOutcome,
    delivery: PhaseOutcome,
    reconnect: PhaseOutcome,
    cleanup: PhaseOutcome,
    persistence: PhaseOutcome,
) -> ProbeReport {
    ProbeReport {
        authentication,
        delivery,
        reconnect,
        cleanup,
        persistence,
    }
}

fn rejected() -> ProbeReport {
    ProbeReport::uniform(PhaseOutcome::Rejected)
}

fn failed() -> ProbeReport {
    ProbeReport::uniform(PhaseOutcome::Failed)
}

fn setting(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn safe_url(value: &str) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

fn endpoint(base: &Url, path: &str) -> Option<Url> {
    base.join(path).ok().filter(|url| {
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn client() -> Result<Client, ()> {
    Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ())
}

fn classified(status: StatusCode) -> PhaseOutcome {
    if status.is_success() {
        PhaseOutcome::Passed
    } else if status.is_client_error() {
        PhaseOutcome::Rejected
    } else {
        PhaseOutcome::Failed
    }
}

fn marker(kind: &str) -> String {
    format!("e6irc-qualification-{kind}-{}", super::now_ms())
}

async fn discord(_target: &str) -> ProbeReport {
    let Some(token) = setting("E6IRC_DISCORD_BOT_TOKEN") else {
        return rejected();
    };
    let Some(channel) = setting("E6IRC_DISCORD_CHANNEL_ID") else {
        return rejected();
    };
    if SafeText::parse(channel.clone(), "E6IRC_DISCORD_CHANNEL_ID").is_err() {
        return rejected();
    }
    let base =
        setting("E6IRC_DISCORD_API_BASE").unwrap_or_else(|| "https://discord.com/api/v10".into());
    let Some(base) = safe_url(&base) else {
        return rejected();
    };
    let Some(gateway) = endpoint(&base, "gateway") else {
        return rejected();
    };
    let Ok(http) = client() else { return failed() };
    let authorization = format!("Bot {token}");
    let Some(channel_url) = endpoint(&base, &format!("channels/{channel}")) else {
        return rejected();
    };
    let auth = match http
        .get(channel_url.clone())
        .header("Authorization", &authorization)
        .send()
        .await
    {
        Ok(response) => classified(response.status()),
        Err(_) => PhaseOutcome::Failed,
    };
    if auth != PhaseOutcome::Passed {
        return report(auth, auth, auth, auth, auth);
    }
    let gateway_url = match http.get(gateway).send().await {
        Ok(response) if response.status().is_success() => response
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|json| json.get("url")?.as_str().map(str::to_owned)),
        Ok(response) => {
            return report(
                PhaseOutcome::Passed,
                classified(response.status()),
                PhaseOutcome::Failed,
                PhaseOutcome::Failed,
                PhaseOutcome::Failed,
            );
        }
        Err(_) => return failed(),
    };
    let Some(gateway_url) = gateway_url else {
        return failed();
    };
    let reconnect = match discord_connect(&gateway_url, &token).await {
        PhaseOutcome::Passed => discord_connect(&gateway_url, &token).await,
        outcome => outcome,
    };
    if reconnect != PhaseOutcome::Passed {
        return report(
            PhaseOutcome::Passed,
            reconnect,
            reconnect,
            reconnect,
            reconnect,
        );
    }
    let message = marker("discord");
    let message_collection = match endpoint(&base, &format!("channels/{channel}/messages")) {
        Some(url) => url,
        None => return rejected(),
    };
    let posted = match http
        .post(message_collection)
        .header("Authorization", &authorization)
        .json(&serde_json::json!({"content": message}))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            response.json::<serde_json::Value>().await.ok()
        }
        Ok(response) => {
            return report(
                PhaseOutcome::Passed,
                classified(response.status()),
                reconnect,
                PhaseOutcome::Failed,
                PhaseOutcome::Failed,
            );
        }
        Err(_) => return failed(),
    };
    let Some(id) = posted.and_then(|json| json.get("id")?.as_str().map(str::to_owned)) else {
        return failed();
    };
    let Some(message_url) = endpoint(&base, &format!("channels/{channel}/messages/{id}")) else {
        return failed();
    };
    let persistence = match http
        .get(message_url.clone())
        .header("Authorization", &authorization)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => PhaseOutcome::Passed,
        Ok(response) => classified(response.status()),
        Err(_) => PhaseOutcome::Failed,
    };
    let cleanup = match http
        .delete(message_url)
        .header("Authorization", &authorization)
        .send()
        .await
    {
        Ok(response) => classified(response.status()),
        Err(_) => PhaseOutcome::Failed,
    };
    report(
        PhaseOutcome::Passed,
        PhaseOutcome::Passed,
        reconnect,
        cleanup,
        persistence,
    )
}

async fn discord_connect(url: &str, token: &str) -> PhaseOutcome {
    let Ok(mut socket) =
        connect_async(format!("{}/?v=10&encoding=json", url.trim_end_matches('/')))
            .await
            .map(|(socket, _)| socket)
    else {
        return PhaseOutcome::Failed;
    };
    let hello = tokio::time::timeout(TIMEOUT, socket.next())
        .await
        .ok()
        .flatten();
    let Some(Ok(Message::Text(frame))) = hello else {
        return PhaseOutcome::Failed;
    };
    if serde_json::from_str::<serde_json::Value>(&frame)
        .ok()
        .and_then(|json| json.get("op").and_then(serde_json::Value::as_i64))
        != Some(10)
    {
        return PhaseOutcome::Rejected;
    }
    let identify = serde_json::json!({"op": 2, "d": {"token": token, "intents": 0, "properties": {"os":"linux", "browser":"e6irc", "device":"e6irc"}}});
    if socket
        .send(Message::Text(identify.to_string().into()))
        .await
        .is_err()
    {
        return PhaseOutcome::Failed;
    }
    let ready = tokio::time::timeout(TIMEOUT, socket.next())
        .await
        .ok()
        .flatten();
    let outcome = match ready {
        Some(Ok(Message::Text(frame)))
            if serde_json::from_str::<serde_json::Value>(&frame)
                .ok()
                .is_some_and(|json| {
                    json.get("t").and_then(serde_json::Value::as_str) == Some("READY")
                }) =>
        {
            PhaseOutcome::Passed
        }
        Some(Ok(_)) => PhaseOutcome::Rejected,
        Some(Err(_)) | None => PhaseOutcome::Failed,
    };
    let _ = socket.close(None).await;
    outcome
}

async fn slack(_target: &str) -> ProbeReport {
    let (Some(bot), Some(app), Some(channel)) = (
        setting("E6IRC_SLACK_BOT_TOKEN"),
        setting("E6IRC_SLACK_APP_TOKEN"),
        setting("E6IRC_SLACK_CHANNEL_ID"),
    ) else {
        return rejected();
    };
    if SafeText::parse(channel.clone(), "E6IRC_SLACK_CHANNEL_ID").is_err() {
        return rejected();
    }
    let base = setting("E6IRC_SLACK_API_BASE").unwrap_or_else(|| "https://slack.com/api/".into());
    let Some(base) = safe_url(&base) else {
        return rejected();
    };
    let Ok(http) = client() else { return failed() };
    let authorization = format!("Bearer {bot}");
    let Some(auth_url) = endpoint(&base, "auth.test") else {
        return rejected();
    };
    let auth = match slack_json(
        http.post(auth_url)
            .header("Authorization", &authorization)
            .send()
            .await,
    )
    .await
    {
        Ok(true) => PhaseOutcome::Passed,
        Ok(false) => PhaseOutcome::Rejected,
        Err(()) => PhaseOutcome::Failed,
    };
    if auth != PhaseOutcome::Passed {
        return report(auth, auth, auth, auth, auth);
    }
    let socket = match slack_socket(&http, &base, &app).await {
        Ok(url) => url,
        Err(outcome) => return report(auth, outcome, outcome, outcome, outcome),
    };
    let reconnect = match slack_connect(&socket).await {
        PhaseOutcome::Passed => slack_connect(&socket).await,
        outcome => outcome,
    };
    if reconnect != PhaseOutcome::Passed {
        return report(auth, reconnect, reconnect, reconnect, reconnect);
    }
    let Some(post_url) = endpoint(&base, "chat.postMessage") else {
        return rejected();
    };
    let message = marker("slack");
    let posted = match http
        .post(post_url)
        .header("Authorization", &authorization)
        .json(&serde_json::json!({"channel":channel,"text":message}))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            response.json::<serde_json::Value>().await.ok()
        }
        Ok(response) => {
            return report(
                auth,
                classified(response.status()),
                reconnect,
                PhaseOutcome::Failed,
                PhaseOutcome::Failed,
            );
        }
        Err(_) => return failed(),
    };
    let Some(timestamp) = posted.and_then(|json| {
        (json.get("ok").and_then(serde_json::Value::as_bool) == Some(true))
            .then_some(json)
            .and_then(|json| {
                json.get("ts")
                    .or_else(|| json.get("message")?.get("ts"))?
                    .as_str()
                    .map(str::to_owned)
            })
    }) else {
        return report(
            auth,
            PhaseOutcome::Rejected,
            reconnect,
            PhaseOutcome::Failed,
            PhaseOutcome::Failed,
        );
    };
    let Some(replies_url) = endpoint(&base, "conversations.replies") else {
        return rejected();
    };
    let persistence = match http
        .get(replies_url)
        .header("Authorization", &authorization)
        .query(&[("channel", &channel), ("ts", &timestamp)])
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            match response.json::<serde_json::Value>().await {
                Ok(json)
                    if json.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
                        && json
                            .get("messages")
                            .and_then(serde_json::Value::as_array)
                            .is_some_and(|messages| {
                                messages.iter().any(|message| {
                                    message.get("ts").and_then(serde_json::Value::as_str)
                                        == Some(&timestamp)
                                })
                            }) =>
                {
                    PhaseOutcome::Passed
                }
                Ok(_) => PhaseOutcome::Rejected,
                Err(_) => PhaseOutcome::Failed,
            }
        }
        Ok(response) => classified(response.status()),
        Err(_) => PhaseOutcome::Failed,
    };
    let Some(delete_url) = endpoint(&base, "chat.delete") else {
        return rejected();
    };
    let cleanup = match http
        .post(delete_url)
        .header("Authorization", &authorization)
        .json(&serde_json::json!({"channel":channel,"ts":timestamp}))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            match response.json::<serde_json::Value>().await {
                Ok(json) if json.get("ok").and_then(serde_json::Value::as_bool) == Some(true) => {
                    PhaseOutcome::Passed
                }
                Ok(_) => PhaseOutcome::Rejected,
                Err(_) => PhaseOutcome::Failed,
            }
        }
        Ok(response) => classified(response.status()),
        Err(_) => PhaseOutcome::Failed,
    };
    report(auth, PhaseOutcome::Passed, reconnect, cleanup, persistence)
}

async fn slack_socket(http: &Client, base: &Url, app: &str) -> Result<String, PhaseOutcome> {
    let Some(url) = endpoint(base, "apps.connections.open") else {
        return Err(PhaseOutcome::Rejected);
    };
    let response = http
        .post(url)
        .header("Authorization", format!("Bearer {app}"))
        .send()
        .await
        .map_err(|_| PhaseOutcome::Failed)?;
    if !response.status().is_success() {
        return Err(classified(response.status()));
    }
    let json = response
        .json::<serde_json::Value>()
        .await
        .map_err(|_| PhaseOutcome::Failed)?;
    if json.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(PhaseOutcome::Rejected);
    }
    json.get("url")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(PhaseOutcome::Failed)
}

async fn slack_connect(url: &str) -> PhaseOutcome {
    match connect_async(url).await {
        Ok((mut socket, _)) => {
            let _ = socket.close(None).await;
            PhaseOutcome::Passed
        }
        Err(_) => PhaseOutcome::Failed,
    }
}

async fn slack_json(response: Result<reqwest::Response, reqwest::Error>) -> Result<bool, ()> {
    let response = response.map_err(|_| ())?;
    if !response.status().is_success() {
        return Ok(false);
    }
    response
        .json::<serde_json::Value>()
        .await
        .map(|json| json.get("ok").and_then(serde_json::Value::as_bool) == Some(true))
        .map_err(|_| ())
}

async fn oidc(target: &str) -> ProbeReport {
    let (Some(client_id), Some(secret)) = (
        setting("E6IRC_OIDC_CLIENT_ID"),
        setting("E6IRC_OIDC_CLIENT_SECRET"),
    ) else {
        return rejected();
    };
    let Some(discovery) = oidc_discovery_url(target) else {
        return rejected();
    };
    let Ok(http) = client() else { return failed() };
    let configuration = match http.get(discovery).send().await {
        Ok(response) if response.status().is_success() => {
            response.json::<serde_json::Value>().await.ok()
        }
        Ok(response) => {
            return report(
                classified(response.status()),
                PhaseOutcome::NotApplicable,
                classified(response.status()),
                classified(response.status()),
                classified(response.status()),
            );
        }
        Err(_) => return failed(),
    };
    let Some(configuration) = configuration else {
        return failed();
    };
    let Some(token_endpoint) = configuration
        .get("token_endpoint")
        .and_then(serde_json::Value::as_str)
        .and_then(safe_url)
    else {
        return rejected();
    };
    let Some(introspection_endpoint) = configuration
        .get("introspection_endpoint")
        .and_then(serde_json::Value::as_str)
        .and_then(safe_url)
    else {
        return rejected();
    };
    let Some(revocation_endpoint) = configuration
        .get("revocation_endpoint")
        .and_then(serde_json::Value::as_str)
        .and_then(safe_url)
    else {
        return rejected();
    };
    let token = match oidc_token(&http, &token_endpoint, &client_id, &secret).await {
        Ok(token) => token,
        Err(outcome) => {
            return report(
                outcome,
                PhaseOutcome::NotApplicable,
                outcome,
                outcome,
                outcome,
            );
        }
    };
    let reconnect = match oidc_token(&http, &token_endpoint, &client_id, &secret).await {
        Ok(_) => PhaseOutcome::Passed,
        Err(outcome) => outcome,
    };
    let persistence = match http
        .post(introspection_endpoint)
        .basic_auth(&client_id, Some(&secret))
        .form(&[("token", token.as_str())])
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => match response
            .json::<serde_json::Value>()
            .await
        {
            Ok(json) if json.get("active").and_then(serde_json::Value::as_bool) == Some(true) => {
                PhaseOutcome::Passed
            }
            Ok(_) => PhaseOutcome::Rejected,
            Err(_) => PhaseOutcome::Failed,
        },
        Ok(response) => classified(response.status()),
        Err(_) => PhaseOutcome::Failed,
    };
    let cleanup = match http
        .post(revocation_endpoint)
        .basic_auth(&client_id, Some(&secret))
        .form(&[("token", token.as_str())])
        .send()
        .await
    {
        Ok(response) => classified(response.status()),
        Err(_) => PhaseOutcome::Failed,
    };
    report(
        PhaseOutcome::Passed,
        PhaseOutcome::NotApplicable,
        reconnect,
        cleanup,
        persistence,
    )
}

fn oidc_discovery_url(target: &str) -> Option<Url> {
    let mut issuer = safe_url(target)?;
    if !issuer.path().ends_with('/') {
        issuer.set_path(&format!("{}/", issuer.path()));
    }
    issuer.join(".well-known/openid-configuration").ok()
}

async fn oidc_token(
    http: &Client,
    endpoint: &Url,
    client_id: &str,
    secret: &str,
) -> Result<String, PhaseOutcome> {
    let response = http
        .post(endpoint.clone())
        .basic_auth(client_id, Some(secret))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .map_err(|_| PhaseOutcome::Failed)?;
    if !response.status().is_success() {
        return Err(classified(response.status()));
    }
    response
        .json::<serde_json::Value>()
        .await
        .map_err(|_| PhaseOutcome::Failed)?
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .ok_or(PhaseOutcome::Rejected)
}

#[cfg(test)]
mod tests {
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
        assert!(safe_url("https://user:secret@issuer.example/api").is_none());
        assert!(safe_url("https://issuer.example/api?token=secret").is_none());
        assert!(safe_url("https://issuer.example/api#secret").is_none());
    }

    #[test]
    fn oidc_discovery_keeps_the_issuer_path() {
        assert_eq!(
            oidc_discovery_url("https://issuer.example/realms/e6")
                .expect("discovery URL")
                .as_str(),
            "https://issuer.example/realms/e6/.well-known/openid-configuration"
        );
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
            .get(endpoint(&base, "channels/42").expect("channel endpoint"))
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
        assert_eq!(
            discord("oracle").await.closed_outcome(TargetKind::Discord),
            super::super::ClosedOutcome::Rejected
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
}
