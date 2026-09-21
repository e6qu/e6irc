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

struct Secret(String);

impl Secret {
    fn setting(name: &str) -> Option<Self> {
        Self::parse(env::var(name).ok()?)
    }

    fn parse(value: String) -> Option<Self> {
        (!value.is_empty() && value.len() <= 4096 && !value.contains(char::is_control))
            .then_some(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

fn environment_value(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
struct DiscordChannelId(String);

impl DiscordChannelId {
    fn parse(value: String) -> Option<Self> {
        decimal_identifier(value).map(Self)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DiscordChannelId {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value).ok_or("invalid Discord channel ID")
    }
}

impl From<DiscordChannelId> for String {
    fn from(value: DiscordChannelId) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
struct DiscordMessageId(String);

impl DiscordMessageId {
    fn parse(value: String) -> Option<Self> {
        decimal_identifier(value).map(Self)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DiscordMessageId {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value).ok_or("invalid Discord message ID")
    }
}

impl From<DiscordMessageId> for String {
    fn from(value: DiscordMessageId) -> Self {
        value.0
    }
}

fn decimal_identifier(value: String) -> Option<String> {
    (value.len() <= 20
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit()))
    .then_some(value)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
struct SlackChannelId(String);

impl SlackChannelId {
    fn parse(value: String) -> Option<Self> {
        (value.len() >= 2
            && value.len() <= 16
            && matches!(value.as_bytes().first(), Some(b'C' | b'G'))
            && value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()))
        .then_some(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SlackChannelId {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value).ok_or("invalid Slack channel ID")
    }
}

impl From<SlackChannelId> for String {
    fn from(value: SlackChannelId) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
struct SlackTimestamp(String);

impl SlackTimestamp {
    fn parse(value: String) -> Option<Self> {
        let (seconds, fraction) = value.split_once('.')?;
        (!seconds.is_empty()
            && !fraction.is_empty()
            && seconds.bytes().all(|byte| byte.is_ascii_digit())
            && fraction.bytes().all(|byte| byte.is_ascii_digit())
            && value.len() <= 32)
            .then_some(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SlackTimestamp {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value).ok_or("invalid Slack timestamp")
    }
}

impl From<SlackTimestamp> for String {
    fn from(value: SlackTimestamp) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointScope {
    Loopback,
    External,
}

/// An endpoint's scope and, for a loopback one, the addresses to dial.
///
/// "This machine" is decided by address, with the native clients' own rule
/// ([`e6irc_client::loopback_addresses`]): every address the host resolves to
/// must be loopback, and the connection then goes to exactly those addresses,
/// so the name cannot be resolved again, differently, afterwards. Anything
/// else is external and must be reached over TLS, which authenticates it by
/// certificate. An external endpoint is named: an address literal outside
/// loopback (a private or public IP) proves no identity and is refused.
async fn endpoint_scope(url: &Url) -> Option<(EndpointScope, Vec<std::net::SocketAddr>)> {
    let host = url.host_str()?;
    let port = url.port_or_known_default()?;
    if let Ok(address) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        return address.to_canonical().is_loopback().then(|| {
            (
                EndpointScope::Loopback,
                vec![std::net::SocketAddr::new(address, port)],
            )
        });
    }
    // `host_str` keeps an IPv6 address's brackets, so this is `host:port`. A
    // name that does not resolve here is not proven loopback, so it is held to
    // the external rule (TLS) rather than refused outright.
    match e6irc_client::loopback_addresses(&format!("{host}:{port}")).await {
        Ok(Some(addresses)) => Some((EndpointScope::Loopback, addresses)),
        Ok(None) | Err(_) => Some((EndpointScope::External, Vec::new())),
    }
}

/// A credential-free campaign endpoint. HTTP is safe only for a loopback oracle.
#[derive(Clone, Debug)]
struct CampaignUrl {
    url: Url,
    scope: EndpointScope,
    /// The loopback addresses a plaintext request is dialled to; empty for a
    /// TLS endpoint.
    pinned: Vec<std::net::SocketAddr>,
    /// The client requests to this endpoint go through: pinned to `pinned`
    /// for a loopback endpoint, resolving by name (and authenticating by
    /// certificate) for a TLS one.
    client: Client,
}

impl CampaignUrl {
    fn new(url: Url, scope: EndpointScope, pinned: Vec<std::net::SocketAddr>) -> Option<Self> {
        let mut builder = Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::none());
        if !pinned.is_empty() {
            builder = builder.resolve_to_addrs(url.host_str()?.trim_matches(['[', ']']), &pinned);
        }
        // As `reqwest::Client::new` does: the builder fails only when the TLS
        // backend cannot initialise, which no campaign can recover from.
        let client = builder
            .build()
            .expect("the HTTP client's TLS backend initialises");
        Some(Self {
            url,
            scope,
            pinned,
            client,
        })
    }

    fn as_url(&self) -> &Url {
        &self.url
    }

    fn as_str(&self) -> &str {
        self.url.as_str()
    }

    fn has_scope(&self, scope: EndpointScope) -> bool {
        self.scope == scope
    }

    /// The same endpoint's origin with another path: keeps the scope, the
    /// pinned addresses and the client, which belong to the origin.
    fn with_url(&self, url: Url) -> Option<Self> {
        (url.origin() == self.url.origin()).then(|| Self {
            url,
            scope: self.scope,
            pinned: self.pinned.clone(),
            client: self.client.clone(),
        })
    }

    fn get(&self) -> RequestBuilder {
        self.client.get(self.url.clone())
    }

    fn post(&self) -> RequestBuilder {
        self.client.post(self.url.clone())
    }

    fn delete(&self) -> RequestBuilder {
        self.client.delete(self.url.clone())
    }
}

fn credential_free(url: &Url) -> bool {
    url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

async fn safe_url(value: &str) -> Option<CampaignUrl> {
    let url = Url::parse(value).ok()?;
    if !credential_free(&url) || url.query().is_some() {
        return None;
    }
    let (scope, pinned) = endpoint_scope(&url).await?;
    if url.scheme() == "https" || (url.scheme() == "http" && scope == EndpointScope::Loopback) {
        CampaignUrl::new(url, scope, pinned)
    } else {
        None
    }
}

#[derive(Clone, Debug)]
struct CampaignSocketUrl {
    url: Url,
    scope: EndpointScope,
    pinned: Vec<std::net::SocketAddr>,
}

impl CampaignSocketUrl {
    async fn parse(value: &str) -> Option<Self> {
        let url = Url::parse(value).ok()?;
        if !credential_free(&url) {
            return None;
        }
        let (scope, pinned) = endpoint_scope(&url).await?;
        (url.scheme() == "wss" || (url.scheme() == "ws" && scope == EndpointScope::Loopback))
            .then_some(Self { url, scope, pinned })
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

    /// Open the socket: a plaintext one to exactly its pinned loopback
    /// addresses, a TLS one by name.
    async fn connect(&self, request: String) -> Result<CampaignSocket, ()> {
        if self.pinned.is_empty() {
            return connect_async(request)
                .await
                .map(|(socket, _)| socket)
                .map_err(|_| ());
        }
        let stream = tokio::net::TcpStream::connect(self.pinned.as_slice())
            .await
            .map_err(|_| ())?;
        tokio_tungstenite::client_async(request, tokio_tungstenite::MaybeTlsStream::Plain(stream))
            .await
            .map(|(socket, _)| socket)
            .map_err(|_| ())
    }
}

async fn oidc_endpoint(issuer: &CampaignUrl, value: &str) -> Option<CampaignUrl> {
    let endpoint = safe_url(value).await?;
    endpoint.has_scope(issuer.scope).then_some(endpoint)
}

fn endpoint(base: &CampaignUrl, path: &str) -> Option<CampaignUrl> {
    base.as_url()
        .join(path)
        .ok()
        .filter(|url| credential_free(url) && url.query().is_none())
        .and_then(|url| base.with_url(url))
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
    id: DiscordMessageId,
    content: String,
}

#[derive(Deserialize)]
struct DiscordMessageCreated {
    id: DiscordMessageId,
}

#[derive(Deserialize, Serialize)]
struct DiscordMessageCreate<'a> {
    content: &'a str,
}

#[derive(Deserialize, Serialize)]
struct DiscordHello {
    op: u8,
    d: DiscordHelloData,
}

#[derive(Deserialize, Serialize)]
struct DiscordHelloData {
    heartbeat_interval: u64,
}

#[derive(Serialize)]
struct DiscordIdentify<'a> {
    op: u8,
    d: DiscordIdentifyData<'a>,
}

#[derive(Serialize)]
struct DiscordIdentifyData<'a> {
    token: &'a str,
    intents: u64,
    properties: DiscordIdentifyProperties,
}

#[derive(Serialize)]
struct DiscordIdentifyProperties {
    os: &'static str,
    browser: &'static str,
    device: &'static str,
}

#[derive(Deserialize)]
struct DiscordGatewayEvent {
    op: u8,
    #[serde(rename = "t")]
    event: Option<DiscordReadyEvent>,
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
    ts: Option<SlackTimestamp>,
    message: Option<SlackMessageTimestamp>,
}

#[derive(Deserialize, Serialize)]
struct SlackMessageTimestamp {
    ts: SlackTimestamp,
}

#[derive(Deserialize, Serialize)]
struct SlackReplies {
    ok: bool,
    messages: Vec<SlackReply>,
}

#[derive(Deserialize, Serialize)]
struct SlackReply {
    ts: SlackTimestamp,
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
    let Some(token) = Secret::setting("E6IRC_DISCORD_BOT_TOKEN") else {
        return not_run(TargetKind::Discord);
    };
    let Some(channel) =
        environment_value("E6IRC_DISCORD_CHANNEL_ID").and_then(DiscordChannelId::parse)
    else {
        return not_run(TargetKind::Discord);
    };
    let base = environment_value("E6IRC_DISCORD_API_BASE")
        .unwrap_or_else(|| "https://discord.com/api/v10".into());
    let Some(base) = safe_url(&base).await else {
        return not_run(TargetKind::Discord);
    };
    let Some(gateway) = endpoint(&base, "gateway") else {
        return not_run(TargetKind::Discord);
    };
    let authorization = format!("Bot {}", token.as_str());
    let Some(channel_url) = endpoint(&base, &format!("channels/{}", channel.as_str())) else {
        return not_run(TargetKind::Discord);
    };
    let auth = request_outcome(channel_url.get().header("Authorization", &authorization)).await;
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
    let gateway_url = match success_json::<DiscordGateway>(gateway.get()).await {
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
    let gateway_url = match gateway_url {
        Some(url) => CampaignSocketUrl::parse(&url).await,
        None => None,
    };
    let Some(gateway_url) = gateway_url else {
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
        message_collection
            .post()
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
        &format!("channels/{}/messages/{}", channel.as_str(), id.as_str()),
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
        message_url.get().header("Authorization", &authorization),
        |json: &DiscordMessage| discord_readback_matches(json, &id, &message),
    )
    .await;
    let cleanup =
        request_outcome(message_url.delete().header("Authorization", &authorization)).await;
    report(
        TargetKind::Discord,
        PhaseOutcome::Passed,
        PhaseOutcome::Passed,
        reconnect,
        cleanup,
        persistence,
    )
}

fn discord_readback_matches(
    message: &DiscordMessage,
    id: &DiscordMessageId,
    content: &str,
) -> bool {
    message.id.0 == id.0 && message.content == content
}

async fn discord_connect(url: &CampaignSocketUrl, token: &Secret) -> PhaseOutcome {
    let Ok(mut socket) = url
        .connect(url.with_query(&[("v", "10"), ("encoding", "json")]))
        .await
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
    let Ok(DiscordHello { op: 10, d: hello }) = serde_json::from_str(&frame) else {
        return PhaseOutcome::Rejected;
    };
    if hello.heartbeat_interval == 0 {
        return PhaseOutcome::Rejected;
    }
    let identify = DiscordIdentify {
        op: 2,
        d: DiscordIdentifyData {
            token: token.as_str(),
            // What the driver identifies with: a campaign that asked for
            // fewer intents proved a session the driver never opens (the
            // Message Content intent is privileged and can be refused).
            intents: e6irc_proto::provider::DISCORD_GATEWAY_INTENTS,
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
    let mut heartbeat = tokio::time::interval(Duration::from_millis(hello.heartbeat_interval));
    heartbeat.tick().await;
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let outcome = loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break PhaseOutcome::Failed,
            _ = heartbeat.tick() => {
                if socket.send(Message::Text(r#"{"op":1,"d":null}"#.into())).await.is_err() {
                    break PhaseOutcome::Failed;
                }
            }
            frame = socket.next() => match frame {
                Some(Ok(Message::Text(frame))) => match serde_json::from_str(&frame) {
                    Ok(DiscordGatewayEvent { op: 0, event: Some(DiscordReadyEvent::Ready) }) => break PhaseOutcome::Passed,
                    Ok(DiscordGatewayEvent { op: 9, .. }) => break PhaseOutcome::Rejected,
                    Ok(DiscordGatewayEvent { op: 1, .. }) => {
                        if socket.send(Message::Text(r#"{"op":1,"d":null}"#.into())).await.is_err() {
                            break PhaseOutcome::Failed;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break PhaseOutcome::Rejected,
                },
                Some(Ok(Message::Close(_))) => break PhaseOutcome::Rejected,
                Some(Ok(_)) | Some(Err(_)) | None => break PhaseOutcome::Failed,
            },
        }
    };
    let _ = socket.close(None).await;
    outcome
}

async fn slack(_target: &str) -> ProbeReport {
    let (Some(bot), Some(app), Some(channel)) = (
        Secret::setting("E6IRC_SLACK_BOT_TOKEN"),
        Secret::setting("E6IRC_SLACK_APP_TOKEN"),
        environment_value("E6IRC_SLACK_CHANNEL_ID").and_then(SlackChannelId::parse),
    ) else {
        return not_run(TargetKind::Slack);
    };
    let base = environment_value("E6IRC_SLACK_API_BASE")
        .unwrap_or_else(|| "https://slack.com/api/".into());
    let Some(base) = safe_url(&base).await else {
        return not_run(TargetKind::Slack);
    };
    let authorization = format!("Bearer {}", bot.as_str());
    let Some(auth_url) = endpoint(&base, "auth.test") else {
        return not_run(TargetKind::Slack);
    };
    let auth = json_outcome(
        auth_url.post().header("Authorization", &authorization),
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
    let reconnect = match slack_connect(&base, &app).await {
        PhaseOutcome::Passed => slack_connect(&base, &app).await,
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
    // Listen before posting: delivery is proven by the marker's own event
    // arriving on a Socket Mode connection and being acked — the path the
    // driver relays through — not by the post's HTTP answer alone.
    let mut listener = match slack_listen(&base, &app).await {
        Ok(listener) => listener,
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
    let message = marker("slack");
    let posted = match success_json::<SlackMessagePost>(
        post_url
            .post()
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
            drop(listener.close(None).await);
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
        drop(listener.close(None).await);
        return report(
            TargetKind::Slack,
            auth,
            PhaseOutcome::Rejected,
            reconnect,
            PhaseOutcome::NotRun,
            PhaseOutcome::NotRun,
        );
    };
    let delivery = slack_await_marker(&mut listener, &message, TIMEOUT).await;
    drop(listener.close(None).await);
    let Some(replies_url) = endpoint(&base, "conversations.replies") else {
        return not_run(TargetKind::Slack);
    };
    let persistence = json_outcome(
        replies_url
            .get()
            .header("Authorization", &authorization)
            .query(&[("channel", channel.as_str()), ("ts", timestamp.as_str())]),
        |json: &SlackReplies| slack_readback_contains(json, &timestamp),
    )
    .await;
    let Some(delete_url) = endpoint(&base, "chat.delete") else {
        return not_run(TargetKind::Slack);
    };
    let cleanup = json_outcome(
        delete_url
            .post()
            .header("Authorization", &authorization)
            .json(&SlackMessageDelete {
                channel: channel.as_str(),
                ts: timestamp.as_str(),
            }),
        |response: &SlackResult| response.ok,
    )
    .await;
    report(
        TargetKind::Slack,
        auth,
        delivery,
        reconnect,
        cleanup,
        persistence,
    )
}

type CampaignSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Open a Socket Mode connection and wait for its `hello`, keeping it open.
async fn slack_listen(base: &CampaignUrl, app: &Secret) -> Result<CampaignSocket, PhaseOutcome> {
    let url = slack_socket(base, app).await?;
    let mut socket = url
        .connect(url.as_str().to_owned())
        .await
        .map_err(|()| PhaseOutcome::Failed)?;
    match tokio::time::timeout(TIMEOUT, socket.next()).await {
        Ok(Some(Ok(Message::Text(frame)))) if slack_hello(&frame) => Ok(socket),
        _ => {
            drop(socket.close(None).await);
            Err(PhaseOutcome::Failed)
        }
    }
}

/// Wait for the `events_api` envelope carrying `marker` and ack it (and
/// every other envelope on the way, as the driver does). `Passed` once the
/// marker's envelope is acked; `Failed` when it does not arrive `within`.
async fn slack_await_marker(
    socket: &mut CampaignSocket,
    marker: &str,
    within: Duration,
) -> PhaseOutcome {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let frame = match tokio::time::timeout_at(deadline, socket.next()).await {
            Ok(Some(Ok(Message::Text(frame)))) => frame,
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(_)) | None) | Err(_) => return PhaseOutcome::Failed,
        };
        let Some((envelope_id, carries_marker)) = slack_envelope(&frame, marker) else {
            continue;
        };
        let Ok(ack) = serde_json::to_string(&SlackAck {
            envelope_id: &envelope_id,
        }) else {
            return PhaseOutcome::Failed;
        };
        if socket.send(Message::Text(ack.into())).await.is_err() {
            return PhaseOutcome::Failed;
        }
        if carries_marker {
            return PhaseOutcome::Passed;
        }
    }
}

#[derive(Serialize)]
struct SlackAck<'a> {
    envelope_id: &'a str,
}

#[derive(Deserialize, Serialize)]
struct SlackEnvelope {
    envelope_id: String,
    #[serde(default)]
    payload: Option<SlackEnvelopePayload>,
}

#[derive(Deserialize, Serialize)]
struct SlackEnvelopePayload {
    #[serde(default)]
    event: Option<SlackEnvelopeEvent>,
}

#[derive(Deserialize, Serialize)]
struct SlackEnvelopeEvent {
    #[serde(default)]
    text: Option<String>,
}

/// An envelope's id and whether its event's text is `marker`; `None` for a
/// frame that is not an envelope (`hello`, `disconnect` without one).
fn slack_envelope(frame: &str, marker: &str) -> Option<(String, bool)> {
    let envelope: SlackEnvelope = serde_json::from_str(frame).ok()?;
    let carries_marker = envelope
        .payload
        .and_then(|payload| payload.event)
        .and_then(|event| event.text)
        .is_some_and(|text| text == marker);
    Some((envelope.envelope_id, carries_marker))
}

fn slack_readback_contains(response: &SlackReplies, timestamp: &SlackTimestamp) -> bool {
    response.ok
        && response
            .messages
            .iter()
            .any(|message| message.ts.0 == timestamp.0)
}

async fn slack_socket(base: &CampaignUrl, app: &Secret) -> Result<CampaignSocketUrl, PhaseOutcome> {
    let Some(url) = endpoint(base, "apps.connections.open") else {
        return Err(PhaseOutcome::Rejected);
    };
    let response = success_json::<SlackSocketOpen>(
        url.post()
            .header("Authorization", format!("Bearer {}", app.as_str())),
    )
    .await?;
    if !response.ok {
        return Err(PhaseOutcome::Rejected);
    }
    let socket = match response.url.as_deref() {
        Some(url) => CampaignSocketUrl::parse(url).await,
        None => None,
    }
    .ok_or(PhaseOutcome::Rejected)?;
    socket
        .has_scope(base.scope)
        .then_some(socket)
        .ok_or(PhaseOutcome::Rejected)
}

async fn slack_connect(base: &CampaignUrl, app: &Secret) -> PhaseOutcome {
    let url = match slack_socket(base, app).await {
        Ok(url) => url,
        Err(outcome) => return outcome,
    };
    match url.connect(url.as_str().to_owned()).await {
        Ok(mut socket) => {
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
        Secret::setting("E6IRC_OIDC_CLIENT_ID"),
        Secret::setting("E6IRC_OIDC_CLIENT_SECRET"),
    ) else {
        return not_run(TargetKind::Oidc);
    };
    let Some(issuer) = safe_url(target).await else {
        return not_run(TargetKind::Oidc);
    };
    let Some(discovery) = oidc_discovery_url(&issuer) else {
        return not_run(TargetKind::Oidc);
    };
    let configuration = match success_json::<OidcDiscovery>(discovery.get()).await {
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
    let Some(token_endpoint) = oidc_endpoint(&issuer, &configuration.token_endpoint).await else {
        return not_run(TargetKind::Oidc);
    };
    let Some(introspection_endpoint) =
        oidc_endpoint(&issuer, &configuration.introspection_endpoint).await
    else {
        return not_run(TargetKind::Oidc);
    };
    let Some(revocation_endpoint) =
        oidc_endpoint(&issuer, &configuration.revocation_endpoint).await
    else {
        return not_run(TargetKind::Oidc);
    };
    let token = match oidc_token(&token_endpoint, &client_id, &secret).await {
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
    let reconnect = match oidc_token(&token_endpoint, &client_id, &secret).await {
        Ok(_) => PhaseOutcome::Passed,
        Err(outcome) => outcome,
    };
    let persistence = json_outcome(
        introspection_endpoint
            .post()
            .basic_auth(client_id.as_str(), Some(secret.as_str()))
            .form(&[("token", token.as_str())]),
        |response: &OidcIntrospection| response.active,
    )
    .await;
    let revoked = request_outcome(
        revocation_endpoint
            .post()
            .basic_auth(client_id.as_str(), Some(secret.as_str()))
            .form(&[("token", token.as_str())]),
    )
    .await;
    let cleanup = if revoked == PhaseOutcome::Passed {
        json_outcome(
            introspection_endpoint
                .post()
                .basic_auth(client_id.as_str(), Some(secret.as_str()))
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
    let mut base = issuer.as_url().clone();
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    base.join(".well-known/openid-configuration")
        .ok()
        .and_then(|url| issuer.with_url(url))
}

async fn oidc_token(
    endpoint: &CampaignUrl,
    client_id: &Secret,
    secret: &Secret,
) -> Result<Secret, PhaseOutcome> {
    let response = success_json::<OidcToken>(
        endpoint
            .post()
            .basic_auth(client_id.as_str(), Some(secret.as_str()))
            .form(&[("grant_type", "client_credentials")]),
    )
    .await?;
    Secret::parse(response.access_token).ok_or(PhaseOutcome::Rejected)
}

#[cfg(test)]
#[path = "../tests/support/native.rs"]
mod tests;
