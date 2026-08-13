use std::env;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, RequestBuilder, StatusCode, Url};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use super::{PhaseOutcome, ProbeReport, QualificationPhase, SafeText, TargetKind};

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
    kind: TargetKind,
    authentication: PhaseOutcome,
    delivery: PhaseOutcome,
    reconnect: PhaseOutcome,
    cleanup: PhaseOutcome,
    persistence: PhaseOutcome,
) -> ProbeReport {
    let outcomes = [authentication, delivery, reconnect, cleanup, persistence];
    if outcomes
        .into_iter()
        .zip(QualificationPhase::ALL)
        .any(|(outcome, phase)| {
            (outcome == PhaseOutcome::NotApplicable) == kind.requires_phase(phase)
        })
    {
        return ProbeReport::not_run(kind);
    }
    ProbeReport {
        authentication,
        delivery,
        reconnect,
        cleanup,
        persistence,
    }
}

fn not_run(kind: TargetKind) -> ProbeReport {
    ProbeReport::not_run(kind)
}

fn failed(kind: TargetKind) -> ProbeReport {
    report(
        kind,
        PhaseOutcome::Failed,
        PhaseOutcome::NotRun,
        PhaseOutcome::NotRun,
        PhaseOutcome::NotRun,
        PhaseOutcome::NotRun,
    )
}

fn setting(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

/// A credential-free campaign endpoint. HTTP is safe only for a loopback oracle.
#[derive(Clone, Debug)]
struct CampaignUrl(Url);

impl CampaignUrl {
    fn as_url(&self) -> &Url {
        &self.0
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn into_url(self) -> Url {
        self.0
    }

    fn is_loopback(&self) -> bool {
        self.0.host_str().is_some_and(is_loopback_host)
    }
}

fn safe_url(value: &str) -> Option<CampaignUrl> {
    let url = Url::parse(value).ok()?;
    let loopback = url.host_str().is_some_and(is_loopback_host);
    ((url.scheme() == "https" || (url.scheme() == "http" && loopback))
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(CampaignUrl(url))
}

#[derive(Clone, Debug)]
struct CampaignSocketUrl(Url);

impl CampaignSocketUrl {
    fn parse(value: &str) -> Option<Self> {
        let url = Url::parse(value).ok()?;
        let loopback = url.host_str().is_some_and(is_loopback_host);
        ((url.scheme() == "wss" || (url.scheme() == "ws" && loopback))
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none())
        .then_some(Self(url))
    }

    fn with_query(&self, values: &[(&str, &str)]) -> String {
        let mut url = self.0.clone();
        url.query_pairs_mut().extend_pairs(values);
        url.into()
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

fn oidc_endpoint(issuer: &CampaignUrl, value: &str) -> Option<CampaignUrl> {
    let endpoint = safe_url(value)?;
    (issuer.is_loopback() == endpoint.is_loopback()).then_some(endpoint)
}

pub(super) fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn endpoint(base: &CampaignUrl, path: &str) -> Option<CampaignUrl> {
    base.as_url()
        .join(path)
        .ok()
        .filter(|url| {
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
        .map(CampaignUrl)
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

async fn request_outcome(request: RequestBuilder) -> PhaseOutcome {
    match request.send().await {
        Ok(response) => classified(response.status()),
        Err(_) => PhaseOutcome::Failed,
    }
}

async fn success_json(request: RequestBuilder) -> Result<serde_json::Value, PhaseOutcome> {
    let response = request.send().await.map_err(|_| PhaseOutcome::Failed)?;
    if !response.status().is_success() {
        return Err(classified(response.status()));
    }
    response.json().await.map_err(|_| PhaseOutcome::Failed)
}

async fn json_outcome(
    request: RequestBuilder,
    accepted: impl FnOnce(&serde_json::Value) -> bool,
) -> PhaseOutcome {
    match success_json(request).await {
        Ok(json) if accepted(&json) => PhaseOutcome::Passed,
        Ok(_) => PhaseOutcome::Rejected,
        Err(outcome) => outcome,
    }
}

fn marker(kind: &str) -> String {
    format!("e6irc-qualification-{kind}-{}", super::now_ms())
}

async fn discord(_target: &str) -> ProbeReport {
    let Some(token) = setting("E6IRC_DISCORD_BOT_TOKEN") else {
        return not_run(TargetKind::Discord);
    };
    let Some(channel) = setting("E6IRC_DISCORD_CHANNEL_ID") else {
        return not_run(TargetKind::Discord);
    };
    if SafeText::parse(channel.clone(), "E6IRC_DISCORD_CHANNEL_ID").is_err() {
        return not_run(TargetKind::Discord);
    }
    let base =
        setting("E6IRC_DISCORD_API_BASE").unwrap_or_else(|| "https://discord.com/api/v10".into());
    let Some(base) = safe_url(&base) else {
        return not_run(TargetKind::Discord);
    };
    let Some(gateway) = endpoint(&base, "gateway") else {
        return not_run(TargetKind::Discord);
    };
    let Ok(http) = client() else {
        return failed(TargetKind::Discord);
    };
    let authorization = format!("Bot {token}");
    let Some(channel_url) = endpoint(&base, &format!("channels/{channel}")) else {
        return not_run(TargetKind::Discord);
    };
    let auth = request_outcome(
        http.get(channel_url.clone().into_url())
            .header("Authorization", &authorization),
    )
    .await;
    if auth != PhaseOutcome::Passed {
        return report(
            TargetKind::Discord,
            auth,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
        );
    }
    let gateway_url = match success_json(http.get(gateway.into_url())).await {
        Ok(json) => json
            .get("url")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        Err(outcome) => {
            return report(
                TargetKind::Discord,
                PhaseOutcome::Passed,
                PhaseOutcome::NotRun,
                outcome,
                PhaseOutcome::NotRun,
                PhaseOutcome::NotRun,
            );
        }
    };
    let Some(gateway_url) = gateway_url.and_then(|url| CampaignSocketUrl::parse(&url)) else {
        return report(
            TargetKind::Discord,
            PhaseOutcome::Passed,
            PhaseOutcome::NotRun,
            PhaseOutcome::Failed,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
        );
    };
    let reconnect = match discord_connect(&gateway_url, &token).await {
        PhaseOutcome::Passed => discord_connect(&gateway_url, &token).await,
        outcome => outcome,
    };
    if reconnect != PhaseOutcome::Passed {
        return report(
            TargetKind::Discord,
            PhaseOutcome::Passed,
            PhaseOutcome::NotRun,
            reconnect,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
        );
    }
    let message = marker("discord");
    let message_collection = match endpoint(&base, &format!("channels/{channel}/messages")) {
        Some(url) => url,
        None => return not_run(TargetKind::Discord),
    };
    let posted = match success_json(
        http.post(message_collection.into_url())
            .header("Authorization", &authorization)
            .json(&serde_json::json!({"content": message})),
    )
    .await
    {
        Ok(json) => Some(json),
        Err(outcome) => {
            return report(
                TargetKind::Discord,
                PhaseOutcome::Passed,
                outcome,
                reconnect,
                PhaseOutcome::NotRun,
                PhaseOutcome::NotRun,
            );
        }
    };
    let Some(id) = posted.and_then(|json| json.get("id")?.as_str().map(str::to_owned)) else {
        return report(
            TargetKind::Discord,
            PhaseOutcome::Passed,
            PhaseOutcome::Failed,
            reconnect,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
        );
    };
    let Some(message_url) = endpoint(&base, &format!("channels/{channel}/messages/{id}")) else {
        return report(
            TargetKind::Discord,
            PhaseOutcome::Passed,
            PhaseOutcome::Failed,
            reconnect,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
        );
    };
    let persistence = json_outcome(
        http.get(message_url.clone().into_url())
            .header("Authorization", &authorization),
        |json| discord_readback_matches(json, &id, &message),
    )
    .await;
    let cleanup = request_outcome(
        http.delete(message_url.into_url())
            .header("Authorization", &authorization),
    )
    .await;
    report(
        TargetKind::Discord,
        PhaseOutcome::Passed,
        PhaseOutcome::Passed,
        reconnect,
        cleanup,
        persistence,
    )
}

fn discord_readback_matches(json: &serde_json::Value, id: &str, content: &str) -> bool {
    json.get("id").and_then(serde_json::Value::as_str) == Some(id)
        && json.get("content").and_then(serde_json::Value::as_str) == Some(content)
}

async fn discord_connect(url: &CampaignSocketUrl, token: &str) -> PhaseOutcome {
    let Ok(mut socket) = connect_async(url.with_query(&[("v", "10"), ("encoding", "json")]))
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
        return not_run(TargetKind::Slack);
    };
    if SafeText::parse(channel.clone(), "E6IRC_SLACK_CHANNEL_ID").is_err() {
        return not_run(TargetKind::Slack);
    }
    let base = setting("E6IRC_SLACK_API_BASE").unwrap_or_else(|| "https://slack.com/api/".into());
    let Some(base) = safe_url(&base) else {
        return not_run(TargetKind::Slack);
    };
    let Ok(http) = client() else {
        return failed(TargetKind::Slack);
    };
    let authorization = format!("Bearer {bot}");
    let Some(auth_url) = endpoint(&base, "auth.test") else {
        return not_run(TargetKind::Slack);
    };
    let auth = json_outcome(
        http.post(auth_url.into_url())
            .header("Authorization", &authorization),
        slack_ok,
    )
    .await;
    if auth != PhaseOutcome::Passed {
        return report(
            TargetKind::Slack,
            auth,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
        );
    }
    let socket = match slack_socket(&http, &base, &app).await {
        Ok(url) => url,
        Err(outcome) => {
            return report(
                TargetKind::Slack,
                auth,
                PhaseOutcome::NotRun,
                outcome,
                PhaseOutcome::NotRun,
                PhaseOutcome::NotRun,
            );
        }
    };
    let reconnect = match slack_connect(&socket).await {
        PhaseOutcome::Passed => slack_connect(&socket).await,
        outcome => outcome,
    };
    if reconnect != PhaseOutcome::Passed {
        return report(
            TargetKind::Slack,
            auth,
            PhaseOutcome::NotRun,
            reconnect,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
        );
    }
    let Some(post_url) = endpoint(&base, "chat.postMessage") else {
        return not_run(TargetKind::Slack);
    };
    let message = marker("slack");
    let posted = match success_json(
        http.post(post_url.into_url())
            .header("Authorization", &authorization)
            .json(&serde_json::json!({"channel":channel,"text":message})),
    )
    .await
    {
        Ok(json) => Some(json),
        Err(outcome) => {
            return report(
                TargetKind::Slack,
                auth,
                outcome,
                reconnect,
                PhaseOutcome::NotRun,
                PhaseOutcome::NotRun,
            );
        }
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
            TargetKind::Slack,
            auth,
            PhaseOutcome::Rejected,
            reconnect,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
        );
    };
    let Some(replies_url) = endpoint(&base, "conversations.replies") else {
        return not_run(TargetKind::Slack);
    };
    let persistence = json_outcome(
        http.get(replies_url.into_url())
            .header("Authorization", &authorization)
            .query(&[("channel", &channel), ("ts", &timestamp)]),
        |json| slack_readback_contains(json, &timestamp),
    )
    .await;
    let Some(delete_url) = endpoint(&base, "chat.delete") else {
        return not_run(TargetKind::Slack);
    };
    let cleanup = json_outcome(
        http.post(delete_url.into_url())
            .header("Authorization", &authorization)
            .json(&serde_json::json!({"channel":channel,"ts":timestamp})),
        slack_ok,
    )
    .await;
    report(
        TargetKind::Slack,
        auth,
        PhaseOutcome::Passed,
        reconnect,
        cleanup,
        persistence,
    )
}

fn slack_readback_contains(json: &serde_json::Value, timestamp: &str) -> bool {
    json.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
        && json
            .get("messages")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|messages| {
                messages.iter().any(|message| {
                    message.get("ts").and_then(serde_json::Value::as_str) == Some(timestamp)
                })
            })
}

fn slack_ok(json: &serde_json::Value) -> bool {
    json.get("ok").and_then(serde_json::Value::as_bool) == Some(true)
}

async fn slack_socket(
    http: &Client,
    base: &CampaignUrl,
    app: &str,
) -> Result<CampaignSocketUrl, PhaseOutcome> {
    let Some(url) = endpoint(base, "apps.connections.open") else {
        return Err(PhaseOutcome::Rejected);
    };
    let json = success_json(
        http.post(url.into_url())
            .header("Authorization", format!("Bearer {app}")),
    )
    .await?;
    if !slack_ok(&json) {
        return Err(PhaseOutcome::Rejected);
    }
    json.get("url")
        .and_then(serde_json::Value::as_str)
        .and_then(CampaignSocketUrl::parse)
        .ok_or(PhaseOutcome::Rejected)
}

async fn slack_connect(url: &CampaignSocketUrl) -> PhaseOutcome {
    match connect_async(url.as_str()).await {
        Ok((mut socket, _)) => {
            let _ = socket.close(None).await;
            PhaseOutcome::Passed
        }
        Err(_) => PhaseOutcome::Failed,
    }
}

async fn oidc(target: &str) -> ProbeReport {
    let (Some(client_id), Some(secret)) = (
        setting("E6IRC_OIDC_CLIENT_ID"),
        setting("E6IRC_OIDC_CLIENT_SECRET"),
    ) else {
        return not_run(TargetKind::Oidc);
    };
    let Some(issuer) = safe_url(target) else {
        return not_run(TargetKind::Oidc);
    };
    let Some(discovery) = oidc_discovery_url(&issuer) else {
        return not_run(TargetKind::Oidc);
    };
    let Ok(http) = client() else {
        return failed(TargetKind::Oidc);
    };
    let configuration = match success_json(http.get(discovery.into_url())).await {
        Ok(json) => json,
        Err(outcome) => {
            return report(
                TargetKind::Oidc,
                outcome,
                PhaseOutcome::NotApplicable,
                PhaseOutcome::NotRun,
                PhaseOutcome::NotRun,
                PhaseOutcome::NotRun,
            );
        }
    };
    if !oidc_issuer_matches(&configuration, &issuer) {
        return not_run(TargetKind::Oidc);
    }
    let Some(token_endpoint) = configuration
        .get("token_endpoint")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| oidc_endpoint(&issuer, value))
    else {
        return not_run(TargetKind::Oidc);
    };
    let Some(introspection_endpoint) = configuration
        .get("introspection_endpoint")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| oidc_endpoint(&issuer, value))
    else {
        return not_run(TargetKind::Oidc);
    };
    let Some(revocation_endpoint) = configuration
        .get("revocation_endpoint")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| oidc_endpoint(&issuer, value))
    else {
        return not_run(TargetKind::Oidc);
    };
    let token = match oidc_token(&http, &token_endpoint, &client_id, &secret).await {
        Ok(token) => token,
        Err(outcome) => {
            return report(
                TargetKind::Oidc,
                outcome,
                PhaseOutcome::NotApplicable,
                PhaseOutcome::NotRun,
                PhaseOutcome::NotRun,
                PhaseOutcome::NotRun,
            );
        }
    };
    let reconnect = match oidc_token(&http, &token_endpoint, &client_id, &secret).await {
        Ok(_) => PhaseOutcome::Passed,
        Err(outcome) => outcome,
    };
    let persistence = json_outcome(
        http.post(introspection_endpoint.clone().into_url())
            .basic_auth(&client_id, Some(&secret))
            .form(&[("token", token.as_str())]),
        |json| json.get("active").and_then(serde_json::Value::as_bool) == Some(true),
    )
    .await;
    let revoked = request_outcome(
        http.post(revocation_endpoint.into_url())
            .basic_auth(&client_id, Some(&secret))
            .form(&[("token", token.as_str())]),
    )
    .await;
    let cleanup = if revoked == PhaseOutcome::Passed {
        json_outcome(
            http.post(introspection_endpoint.into_url())
                .basic_auth(&client_id, Some(&secret))
                .form(&[("token", token.as_str())]),
            |json| json.get("active").and_then(serde_json::Value::as_bool) == Some(false),
        )
        .await
    } else {
        revoked
    };
    report(
        TargetKind::Oidc,
        PhaseOutcome::Passed,
        PhaseOutcome::NotApplicable,
        reconnect,
        cleanup,
        persistence,
    )
}

fn oidc_issuer_matches(configuration: &serde_json::Value, issuer: &CampaignUrl) -> bool {
    configuration
        .get("issuer")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value == issuer.as_str())
}

fn oidc_discovery_url(issuer: &CampaignUrl) -> Option<CampaignUrl> {
    let mut issuer = issuer.as_url().clone();
    if !issuer.path().ends_with('/') {
        issuer.set_path(&format!("{}/", issuer.path()));
    }
    issuer
        .join(".well-known/openid-configuration")
        .ok()
        .map(CampaignUrl)
}

async fn oidc_token(
    http: &Client,
    endpoint: &CampaignUrl,
    client_id: &str,
    secret: &str,
) -> Result<String, PhaseOutcome> {
    success_json(
        http.post(endpoint.clone().into_url())
            .basic_auth(client_id, Some(secret))
            .form(&[("grant_type", "client_credentials")]),
    )
    .await?
    .get("access_token")
    .and_then(serde_json::Value::as_str)
    .filter(|token| !token.is_empty())
    .map(str::to_owned)
    .ok_or(PhaseOutcome::Rejected)
}

#[cfg(test)]
#[path = "../tests/support/native.rs"]
mod tests;
