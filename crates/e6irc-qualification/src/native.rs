use std::env;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, RequestBuilder, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use super::{PhaseOutcome, ProbeReport, QualificationPhase, TargetKind};

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

#[derive(Clone, Debug)]
struct ProviderChannelId(String);

impl ProviderChannelId {
    fn parse(value: String) -> Option<Self> {
        (value.len() <= 255 && value.bytes().all(|byte| byte.is_ascii_alphanumeric()))
            .then_some(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointScope {
    Loopback,
    External,
}

impl EndpointScope {
    fn parse_host(host: &str) -> Option<Self> {
        if is_loopback_host(host) {
            return Some(Self::Loopback);
        }
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_err()
            .then_some(Self::External)
    }
}

/// A credential-free campaign endpoint. HTTP is safe only for a loopback oracle.
#[derive(Clone, Debug)]
struct CampaignUrl {
    url: Url,
    scope: EndpointScope,
}

impl CampaignUrl {
    fn as_url(&self) -> &Url {
        &self.url
    }

    fn as_str(&self) -> &str {
        self.url.as_str()
    }

    fn into_url(self) -> Url {
        self.url
    }

    fn has_scope(&self, scope: EndpointScope) -> bool {
        self.scope == scope
    }
}

fn safe_url(value: &str) -> Option<CampaignUrl> {
    let url = Url::parse(value).ok()?;
    let scope = url.host_str().and_then(EndpointScope::parse_host)?;
    ((url.scheme() == "https" || (url.scheme() == "http" && scope == EndpointScope::Loopback))
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(CampaignUrl { url, scope })
}

#[derive(Clone, Debug)]
struct CampaignSocketUrl {
    url: Url,
    scope: EndpointScope,
}

impl CampaignSocketUrl {
    fn parse(value: &str) -> Option<Self> {
        let url = Url::parse(value).ok()?;
        let scope = url.host_str().and_then(EndpointScope::parse_host)?;
        ((url.scheme() == "wss" || (url.scheme() == "ws" && scope == EndpointScope::Loopback))
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none())
        .then_some(Self { url, scope })
    }

    fn with_query(&self, values: &[(&str, &str)]) -> String {
        let mut url = self.url.clone();
        url.query_pairs_mut().extend_pairs(values);
        url.into()
    }

    fn as_str(&self) -> &str {
        self.url.as_str()
    }

    fn has_scope(&self, scope: EndpointScope) -> bool {
        self.scope == scope
    }
}

fn oidc_endpoint(issuer: &CampaignUrl, value: &str) -> Option<CampaignUrl> {
    let endpoint = safe_url(value)?;
    endpoint.has_scope(issuer.scope).then_some(endpoint)
}

pub(super) fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

pub(super) fn is_external_host(host: &str) -> bool {
    EndpointScope::parse_host(host) == Some(EndpointScope::External)
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
        .and_then(|url| {
            let scope = url.host_str().and_then(EndpointScope::parse_host)?;
            (scope == base.scope).then_some(CampaignUrl { url, scope })
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

async fn request_outcome(request: RequestBuilder) -> PhaseOutcome {
    match request.send().await {
        Ok(response) => classified(response.status()),
        Err(_) => PhaseOutcome::Failed,
    }
}

async fn success_json<T: DeserializeOwned>(request: RequestBuilder) -> Result<T, PhaseOutcome> {
    let response = request.send().await.map_err(|_| PhaseOutcome::Failed)?;
    if !response.status().is_success() {
        return Err(classified(response.status()));
    }
    response.json().await.map_err(|_| PhaseOutcome::Failed)
}

async fn json_outcome<T: DeserializeOwned>(
    request: RequestBuilder,
    accepted: impl FnOnce(&T) -> bool,
) -> PhaseOutcome {
    match success_json(request).await {
        Ok(json) if accepted(&json) => PhaseOutcome::Passed,
        Ok(_) => PhaseOutcome::Rejected,
        Err(outcome) => outcome,
    }
}

#[derive(Deserialize, Serialize)]
struct DiscordGateway {
    url: String,
}

#[derive(Deserialize, Serialize)]
struct DiscordMessage {
    id: String,
    content: String,
}

#[derive(Deserialize)]
struct DiscordMessageCreated {
    id: String,
}

#[derive(Deserialize, Serialize)]
struct DiscordMessageCreate<'a> {
    content: &'a str,
}

#[derive(Deserialize, Serialize)]
struct DiscordHello {
    op: u8,
}

#[derive(Serialize)]
struct DiscordIdentify<'a> {
    op: u8,
    d: DiscordIdentifyData<'a>,
}

#[derive(Serialize)]
struct DiscordIdentifyData<'a> {
    token: &'a str,
    intents: u8,
    properties: DiscordIdentifyProperties,
}

#[derive(Serialize)]
struct DiscordIdentifyProperties {
    os: &'static str,
    browser: &'static str,
    device: &'static str,
}

#[derive(Deserialize)]
struct DiscordReady {
    #[serde(rename = "t")]
    event: DiscordReadyEvent,
}

#[derive(Deserialize)]
enum DiscordReadyEvent {
    #[serde(rename = "READY")]
    Ready,
}

#[derive(Serialize)]
struct SlackMessageCreate<'a> {
    channel: &'a str,
    text: &'a str,
}

#[derive(Serialize)]
struct SlackMessageDelete<'a> {
    channel: &'a str,
    ts: &'a str,
}

#[derive(Deserialize, Serialize)]
struct SlackResult {
    ok: bool,
}

#[derive(Deserialize, Serialize)]
struct SlackSocketOpen {
    ok: bool,
    url: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct SlackMessagePost {
    ok: bool,
    ts: Option<String>,
    message: Option<SlackMessageTimestamp>,
}

#[derive(Deserialize, Serialize)]
struct SlackMessageTimestamp {
    ts: String,
}

#[derive(Deserialize, Serialize)]
struct SlackReplies {
    ok: bool,
    messages: Vec<SlackReply>,
}

#[derive(Deserialize, Serialize)]
struct SlackReply {
    ts: String,
}

#[derive(Deserialize, Serialize)]
struct OidcDiscovery {
    issuer: String,
    token_endpoint: String,
    introspection_endpoint: String,
    revocation_endpoint: String,
}

#[derive(Deserialize, Serialize)]
struct OidcToken {
    access_token: String,
}

#[derive(Deserialize, Serialize)]
struct OidcIntrospection {
    active: bool,
}

fn marker(kind: &str) -> String {
    format!("e6irc-qualification-{kind}-{}", super::now_ms())
}

async fn discord(_target: &str) -> ProbeReport {
    let Some(token) = setting("E6IRC_DISCORD_BOT_TOKEN") else {
        return not_run(TargetKind::Discord);
    };
    let Some(channel) = setting("E6IRC_DISCORD_CHANNEL_ID").and_then(ProviderChannelId::parse)
    else {
        return not_run(TargetKind::Discord);
    };
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
    let Some(channel_url) = endpoint(&base, &format!("channels/{}", channel.as_str())) else {
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
    let gateway_url = match success_json::<DiscordGateway>(http.get(gateway.into_url())).await {
        Ok(json) => Some(json.url),
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
    if !gateway_url.has_scope(base.scope) {
        return report(
            TargetKind::Discord,
            PhaseOutcome::Passed,
            PhaseOutcome::NotRun,
            PhaseOutcome::Failed,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
        );
    }
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
    let message_collection =
        match endpoint(&base, &format!("channels/{}/messages", channel.as_str())) {
            Some(url) => url,
            None => return not_run(TargetKind::Discord),
        };
    let posted = match success_json::<DiscordMessageCreated>(
        http.post(message_collection.into_url())
            .header("Authorization", &authorization)
            .json(&DiscordMessageCreate { content: &message }),
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
    let Some(DiscordMessageCreated { id }) = posted else {
        return report(
            TargetKind::Discord,
            PhaseOutcome::Passed,
            PhaseOutcome::Failed,
            reconnect,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
        );
    };
    let Some(message_url) = endpoint(
        &base,
        &format!("channels/{}/messages/{id}", channel.as_str()),
    ) else {
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
        |json: &DiscordMessage| discord_readback_matches(json, &id, &message),
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

fn discord_readback_matches(message: &DiscordMessage, id: &str, content: &str) -> bool {
    message.id == id && message.content == content
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
    if !matches!(serde_json::from_str(&frame), Ok(DiscordHello { op: 10 })) {
        return PhaseOutcome::Rejected;
    }
    let identify = DiscordIdentify {
        op: 2,
        d: DiscordIdentifyData {
            token,
            intents: 0,
            properties: DiscordIdentifyProperties {
                os: "linux",
                browser: "e6irc",
                device: "e6irc",
            },
        },
    };
    let Ok(identify) = serde_json::to_string(&identify) else {
        return PhaseOutcome::Failed;
    };
    if socket.send(Message::Text(identify.into())).await.is_err() {
        return PhaseOutcome::Failed;
    }
    let ready = tokio::time::timeout(TIMEOUT, socket.next())
        .await
        .ok()
        .flatten();
    let outcome = match ready {
        Some(Ok(Message::Text(frame)))
            if matches!(
                serde_json::from_str(&frame),
                Ok(DiscordReady {
                    event: DiscordReadyEvent::Ready
                })
            ) =>
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
        setting("E6IRC_SLACK_CHANNEL_ID").and_then(ProviderChannelId::parse),
    ) else {
        return not_run(TargetKind::Slack);
    };
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
        |response: &SlackResult| response.ok,
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
    let reconnect = match slack_connect(&http, &base, &app).await {
        PhaseOutcome::Passed => slack_connect(&http, &base, &app).await,
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
    let posted = match success_json::<SlackMessagePost>(
        http.post(post_url.into_url())
            .header("Authorization", &authorization)
            .json(&SlackMessageCreate {
                channel: channel.as_str(),
                text: &message,
            }),
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
        json.ok
            .then(|| json.ts.or_else(|| json.message.map(|message| message.ts)))
            .flatten()
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
            .query(&[("channel", channel.as_str()), ("ts", &timestamp)]),
        |json: &SlackReplies| slack_readback_contains(json, &timestamp),
    )
    .await;
    let Some(delete_url) = endpoint(&base, "chat.delete") else {
        return not_run(TargetKind::Slack);
    };
    let cleanup = json_outcome(
        http.post(delete_url.into_url())
            .header("Authorization", &authorization)
            .json(&SlackMessageDelete {
                channel: channel.as_str(),
                ts: &timestamp,
            }),
        |response: &SlackResult| response.ok,
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

fn slack_readback_contains(response: &SlackReplies, timestamp: &str) -> bool {
    response.ok
        && response
            .messages
            .iter()
            .any(|message| message.ts == timestamp)
}

async fn slack_socket(
    http: &Client,
    base: &CampaignUrl,
    app: &str,
) -> Result<CampaignSocketUrl, PhaseOutcome> {
    let Some(url) = endpoint(base, "apps.connections.open") else {
        return Err(PhaseOutcome::Rejected);
    };
    let response = success_json::<SlackSocketOpen>(
        http.post(url.into_url())
            .header("Authorization", format!("Bearer {app}")),
    )
    .await?;
    if !response.ok {
        return Err(PhaseOutcome::Rejected);
    }
    let socket = response
        .url
        .as_deref()
        .and_then(CampaignSocketUrl::parse)
        .ok_or(PhaseOutcome::Rejected)?;
    socket
        .has_scope(base.scope)
        .then_some(socket)
        .ok_or(PhaseOutcome::Rejected)
}

async fn slack_connect(http: &Client, base: &CampaignUrl, app: &str) -> PhaseOutcome {
    let url = match slack_socket(http, base, app).await {
        Ok(url) => url,
        Err(outcome) => return outcome,
    };
    match connect_async(url.as_str()).await {
        Ok((mut socket, _)) => {
            let hello = tokio::time::timeout(TIMEOUT, socket.next())
                .await
                .ok()
                .flatten();
            let connected = matches!(
                hello,
                Some(Ok(Message::Text(frame))) if slack_hello(&frame)
            );
            let _ = socket.close(None).await;
            if connected {
                PhaseOutcome::Passed
            } else {
                PhaseOutcome::Failed
            }
        }
        Err(_) => PhaseOutcome::Failed,
    }
}

#[derive(serde::Deserialize, Serialize)]
struct SlackHello {
    #[serde(rename = "type")]
    kind: SlackSocketFrame,
}

#[derive(serde::Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SlackSocketFrame {
    Hello,
}

fn slack_hello(frame: &str) -> bool {
    matches!(
        serde_json::from_str(frame),
        Ok(SlackHello {
            kind: SlackSocketFrame::Hello
        })
    )
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
    let configuration = match success_json::<OidcDiscovery>(http.get(discovery.into_url())).await {
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
    let Some(token_endpoint) = oidc_endpoint(&issuer, &configuration.token_endpoint) else {
        return not_run(TargetKind::Oidc);
    };
    let Some(introspection_endpoint) =
        oidc_endpoint(&issuer, &configuration.introspection_endpoint)
    else {
        return not_run(TargetKind::Oidc);
    };
    let Some(revocation_endpoint) = oidc_endpoint(&issuer, &configuration.revocation_endpoint)
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
        |response: &OidcIntrospection| response.active,
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
            |response: &OidcIntrospection| !response.active,
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

fn oidc_issuer_matches(configuration: &OidcDiscovery, issuer: &CampaignUrl) -> bool {
    configuration.issuer == issuer.as_str()
}

fn oidc_discovery_url(issuer: &CampaignUrl) -> Option<CampaignUrl> {
    let scope = issuer.scope;
    let mut issuer = issuer.as_url().clone();
    if !issuer.path().ends_with('/') {
        issuer.set_path(&format!("{}/", issuer.path()));
    }
    issuer
        .join(".well-known/openid-configuration")
        .ok()
        .map(|url| CampaignUrl { url, scope })
}

async fn oidc_token(
    http: &Client,
    endpoint: &CampaignUrl,
    client_id: &str,
    secret: &str,
) -> Result<String, PhaseOutcome> {
    let response = success_json::<OidcToken>(
        http.post(endpoint.clone().into_url())
            .basic_auth(client_id, Some(secret))
            .form(&[("grant_type", "client_credentials")]),
    )
    .await?;
    (!response.access_token.is_empty())
        .then_some(response.access_token)
        .ok_or(PhaseOutcome::Rejected)
}

#[cfg(test)]
#[path = "../tests/support/native.rs"]
mod tests;
