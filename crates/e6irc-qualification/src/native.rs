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
                Ok(json) if slack_readback_contains(&json, &timestamp) => PhaseOutcome::Passed,
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
#[path = "../tests/support/native.rs"]
mod tests;
