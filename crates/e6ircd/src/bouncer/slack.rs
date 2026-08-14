//! Slack Socket Mode bridge.
//!
//! CI drives its HTTP and WebSocket contract through a local protocol oracle.

use super::BoundedJson;
use std::collections::HashMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio_tungstenite::tungstenite::Message as Ws;

use super::{ConnectionEvent, DriverEnds, NetworkDriver, NetworkHandle};

/// Default Slack Web API base; overridable via config `addr`.
const DEFAULT_API: &str = "https://slack.com/api";

#[derive(Debug, Clone)]
pub struct SlackConfig {
    /// Bot token (`xoxb-…`), for Web API calls.
    pub bot_token: String,
    /// App-level token (`xapp-…`), for opening the Socket Mode connection.
    pub app_token: String,
    /// Web API base; empty means [`DEFAULT_API`].
    pub api_base: String,
    /// Slack channel ids to bridge.
    pub channels: Vec<String>,
    pub buffer_cap: usize,
}

pub struct SlackDriver {
    config: SlackConfig,
}

impl SlackDriver {
    pub fn new(config: SlackConfig) -> Self {
        Self { config }
    }
}

impl NetworkDriver for SlackDriver {
    fn kind(&self) -> &'static str {
        "slack"
    }

    super::bridge_start!();
}

super::bridge_run!(SlackConfig);

async fn session_once(config: &SlackConfig, ends: &mut DriverEnds) -> super::SessionOutcome {
    use super::NetworkFailure;
    use super::SessionOutcome::Dropped;
    let http = match super::bridge_http_or_outcome("slack", Duration::from_secs(30)) {
        Ok(c) => c,
        Err(outcome) => return outcome,
    };
    let base = super::bridge_api_base(&config.api_base, DEFAULT_API);

    let (id_to_channel, channel_to_id) = match super::resolve_bridge_channels(
        "slack",
        &config.channels,
        |id| {
            let http = &http;
            let base = &base;
            let token = &config.bot_token;
            async move { fetch_channel_name(http, base, token, &id).await }
        },
        |id, error| slack_failure(&format!("channel {id} lookup failed"), error),
    )
    .await
    {
        Ok(maps) => maps,
        Err(outcome) => return outcome,
    };

    let ws_url = match open_socket(&http, &base, &config.app_token).await {
        Ok(u) => u,
        Err(e) => {
            return slack_failure("apps.connections.open failed", &e);
        }
    };
    let ws = match super::bridge_ws_open(&ws_url, "slack", "socket").await {
        Ok(ws) => ws,
        Err(outcome) => return outcome,
    };
    let (mut write, mut read) = ws.split();
    ends.emit(ConnectionEvent::Connected);

    let mut user_names: HashMap<String, String> = HashMap::new();

    let read_timeout = Duration::from_secs(90);
    loop {
        tokio::select! {
            text = super::next_bridge_text(&mut read, &mut write, read_timeout, "slack", "socket", |_| {
                Dropped(NetworkFailure::ConnectionLost)
            }) => {
                let text = match text {
                    Ok(Some(t)) => t,
                    Ok(None) => continue,
                    Err(outcome) => return outcome,
                };
                let envelope = match parse_envelope(&text) {
                    Ok(envelope) => envelope,
                    Err(e) => {
                        eprintln!("slack: malformed Socket Mode frame: {e}");
                        return Dropped(NetworkFailure::UpstreamProtocolFailed);
                    }
                };
                if let Some(ack_id) = &envelope.ack {
                    let ack = match socket_ack(ack_id) {
                        Ok(ack) => ack,
                        Err(error) => {
                            eprintln!("slack: could not encode Socket Mode ACK: {error}");
                            return Dropped(NetworkFailure::UpstreamProtocolFailed);
                        }
                    };
                    if write.send(ack).await.is_err() {
                        return Dropped(NetworkFailure::UpstreamWriteFailed);
                    }
                }
                if envelope.disconnect {
                    return Dropped(NetworkFailure::ConnectionLost);
                }
                if let Some(m) = envelope.message
                    && let Some(channel) = id_to_channel.get(&m.channel).cloned()
                {
                    let sender = match user_names.get(&m.user) {
                        Some(name) => name.clone(),
                        None => {
                            let name =
                                match fetch_user_name(&http, &base, &config.bot_token, &m.user).await
                                {
                                    Ok(name) => name,
                                    Err(e) => {
                                        eprintln!("slack: users.info for {} failed: {e}", m.user);
                                        ends.record_error(NetworkFailure::UpstreamRequestFailed);
                                        m.user.clone()
                                    }
                                };
                            user_names.insert(m.user.clone(), name.clone());
                            name
                        }
                    };
                    for line in super::render_bridged_privmsg("slack", &sender, &channel, &m.text) {
                        ends.emit_line(line);
                    }
                }
            }
            cmd = ends.next_command() => match cmd {
                Some(cmd) => {
                    let routed = super::route_privmsg(&cmd.line, &channel_to_id);
                    super::relay_routed(ends, routed, "Slack", "channel", |id, text| {
                        let http = http.clone();
                        let base = base.clone();
                        let bot_token = config.bot_token.clone();
                        async move { post_message(&http, &base, &bot_token, &id, &text).await }
                    })
                    .await;
                }
                None => return super::SessionOutcome::Stopped, // every handle dropped
            },
        }
    }
}

struct SlackMessage {
    channel: String,
    user: String,
    text: String,
}

struct Envelope {
    ack: Option<String>,
    disconnect: bool,
    message: Option<SlackMessage>,
}

#[derive(Serialize)]
struct SocketAck<'a> {
    envelope_id: &'a str,
}

fn socket_ack(envelope_id: &str) -> Result<Ws, String> {
    serde_json::to_string(&SocketAck { envelope_id })
        .map(Ws::text)
        .map_err(|error| format!("Socket Mode ACK: {error}"))
}

#[derive(serde::Deserialize)]
struct SocketFrame {
    #[serde(rename = "type")]
    kind: SocketFrameKind,
    #[serde(default)]
    envelope_id: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum SocketFrameKind {
    Disconnect,
    EventsApi,
    #[serde(other)]
    Other,
}

#[derive(serde::Deserialize)]
struct EventsApiFrame {
    envelope_id: String,
    payload: SocketPayload,
}

#[derive(serde::Deserialize)]
struct SocketPayload {
    event: SlackEvent,
}

#[derive(serde::Deserialize)]
struct SlackEvent {
    #[serde(rename = "type")]
    kind: SlackEventKind,
    #[serde(default)]
    bot_id: Option<String>,
    #[serde(default)]
    subtype: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum SlackEventKind {
    Message,
    #[serde(other)]
    Other,
}

fn parse_envelope(text: &str) -> Result<Envelope, String> {
    let frame: SocketFrame =
        serde_json::from_str(text).map_err(|e| format!("Socket Mode JSON: {e}"))?;
    if matches!(frame.kind, SocketFrameKind::Disconnect) {
        return Ok(Envelope {
            ack: frame.envelope_id,
            disconnect: true,
            message: None,
        });
    }
    if matches!(frame.kind, SocketFrameKind::Other) {
        return Ok(Envelope {
            ack: frame.envelope_id,
            disconnect: false,
            message: None,
        });
    }

    let events: EventsApiFrame =
        serde_json::from_str(text).map_err(|e| format!("events_api frame: {e}"))?;
    let ack = events.envelope_id;
    let event = events.payload.event;
    let message = if matches!(event.kind, SlackEventKind::Message)
        && event.bot_id.is_none()
        && event.subtype.is_none()
    {
        Some(SlackMessage {
            channel: event.channel.ok_or("user message event had no channel")?,
            user: event.user.ok_or("user message event had no user")?,
            text: event.text.ok_or("user message event had no text")?,
        })
    } else {
        None
    };
    Ok(Envelope {
        ack: Some(ack),
        disconnect: false,
        message,
    })
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum SlackResponse<T> {
    Success(SlackSuccess<T>),
    Failure(SlackFailure),
}

#[derive(serde::Deserialize)]
struct SlackSuccess<T> {
    #[serde(rename = "ok", deserialize_with = "true_only")]
    _ok: (),
    #[serde(flatten)]
    value: T,
}

#[derive(serde::Deserialize)]
struct SlackFailure {
    #[serde(rename = "ok", deserialize_with = "false_only")]
    _ok: (),
    #[serde(default)]
    error: Option<String>,
}

fn true_only<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
    if bool::deserialize(deserializer)? {
        Ok(())
    } else {
        Err(serde::de::Error::custom("expected ok=true"))
    }
}

fn false_only<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
    if bool::deserialize(deserializer)? {
        Err(serde::de::Error::custom("expected ok=false"))
    } else {
        Ok(())
    }
}

impl<T> SlackResponse<T> {
    fn into_result(self) -> Result<T, String> {
        match self {
            Self::Success(response) => Ok(response.value),
            Self::Failure(response) => {
                Err(response.error.unwrap_or_else(|| "slack api error".into()))
            }
        }
    }
}

async fn decode_slack_response<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, String> {
    response
        .bounded_json::<SlackResponse<T>>()
        .await?
        .into_result()
}

fn slack_failure(context: &str, err: &str) -> super::SessionOutcome {
    const AUTH_ERRORS: &[&str] = &[
        "invalid_auth",
        "not_authed",
        "account_inactive",
        "token_revoked",
        "token_expired",
        "invalid_token",
        "no_permission",
    ];
    if AUTH_ERRORS.contains(&err) {
        eprintln!("slack: {context}: {err} (auth rejected; will stop retrying)");
        super::SessionOutcome::AuthRejected
    } else {
        eprintln!("slack: {context}: {err}");
        super::SessionOutcome::Dropped(super::NetworkFailure::UpstreamRequestFailed)
    }
}

async fn open_socket(
    http: &reqwest::Client,
    base: &str,
    app_token: &str,
) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct SocketOpen {
        url: String,
    }

    decode_slack_response::<SocketOpen>(
        http.post(format!("{base}/apps.connections.open"))
            .header("Authorization", format!("Bearer {app_token}"))
            .send()
            .await
            .map_err(|e| e.to_string())?,
    )
    .await
    .map(|response| response.url)
}

async fn fetch_channel_name(
    http: &reqwest::Client,
    base: &str,
    bot_token: &str,
    id: &str,
) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct ChannelInfo {
        channel: SlackChannel,
    }
    #[derive(serde::Deserialize)]
    struct SlackChannel {
        name: String,
    }

    let response: ChannelInfo = slack_get_json(
        http,
        base,
        bot_token,
        "conversations.info",
        &[("channel", id)],
    )
    .await?;
    if response.channel.name.is_empty() {
        Err(format!("conversations.info for {id} had an empty name"))
    } else {
        Ok(response.channel.name)
    }
}

async fn slack_get_json<T: DeserializeOwned>(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    method: &str,
    query: &[(&str, &str)],
) -> Result<T, String> {
    decode_slack_response(
        http.get(format!("{base}/{method}"))
            .header("Authorization", format!("Bearer {token}"))
            .query(query)
            .send()
            .await
            .map_err(|e| e.to_string())?,
    )
    .await
}

async fn fetch_user_name(
    http: &reqwest::Client,
    base: &str,
    bot_token: &str,
    id: &str,
) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct UserInfo {
        user: SlackUser,
    }
    #[derive(serde::Deserialize)]
    struct SlackUser {
        #[serde(default)]
        profile: SlackProfile,
        #[serde(default)]
        name: Option<String>,
    }
    #[derive(Default, serde::Deserialize)]
    struct SlackProfile {
        #[serde(default)]
        display_name: Option<String>,
        #[serde(default)]
        real_name: Option<String>,
    }

    let response: UserInfo =
        slack_get_json(http, base, bot_token, "users.info", &[("user", id)]).await?;
    [
        response.user.profile.display_name,
        response.user.profile.real_name,
        response.user.name,
    ]
    .into_iter()
    .flatten()
    .find(|name| !name.is_empty())
    .ok_or_else(|| format!("users.info for {id} had no name"))
}

async fn post_message(
    http: &reqwest::Client,
    base: &str,
    bot_token: &str,
    channel_id: &str,
    text: &str,
) -> Result<(), String> {
    #[derive(Serialize)]
    struct PostMessage<'a> {
        channel: &'a str,
        text: &'a str,
    }

    let req = http
        .post(format!("{base}/chat.postMessage"))
        .header("Authorization", format!("Bearer {bot_token}"))
        .json(&PostMessage {
            channel: channel_id,
            text,
        });
    #[derive(serde::Deserialize)]
    struct Accepted {}

    decode_slack_response::<Accepted>(super::bridge_send(req).await?).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_message_envelope() {
        let e = parse_envelope(
            r#"{"envelope_id":"abc","type":"events_api","payload":{"event":
               {"type":"message","channel":"C1","user":"U1","text":"hi"}}}"#,
        )
        .expect("message envelope");
        assert_eq!(e.ack.as_deref(), Some("abc"));
        assert!(!e.disconnect);
        let m = e.message.expect("message");
        assert_eq!(m.channel, "C1");
        assert_eq!(m.user, "U1");
        assert_eq!(m.text, "hi");
    }

    #[test]
    fn drops_bot_and_subtyped_messages() {
        // Our own / other bots' posts carry bot_id.
        let e = parse_envelope(
            r#"{"envelope_id":"x","type":"events_api","payload":{"event":
               {"type":"message","channel":"C1","bot_id":"B9","text":"echo"}}}"#,
        )
        .expect("bot message");
        assert_eq!(e.ack.as_deref(), Some("x")); // still ack it
        assert!(e.message.is_none());
        // Edits/joins carry a subtype.
        let e = parse_envelope(
            r#"{"envelope_id":"y","type":"events_api","payload":{"event":
               {"type":"message","subtype":"channel_join","channel":"C1","user":"U1"}}}"#,
        )
        .expect("subtyped message");
        assert!(e.message.is_none());
    }

    #[test]
    fn handles_disconnect_and_garbage() {
        let e = parse_envelope(r#"{"type":"disconnect","reason":"refresh"}"#).expect("disconnect");
        assert!(e.disconnect);
        let e = parse_envelope(r#"{"type":"hello","num_connections":1}"#).expect("hello");
        assert!(e.ack.is_none() && !e.disconnect && e.message.is_none());
        let e = parse_envelope(
            r#"{"envelope_id":"cmd","type":"slash_commands",
               "payload":{"command":"/ignored"}}"#,
        )
        .expect("unknown envelope");
        assert_eq!(e.ack.as_deref(), Some("cmd"));
        assert!(e.message.is_none());
        assert!(parse_envelope("not json").is_err());
    }

    #[test]
    fn rejects_malformed_user_messages_instead_of_defaulting_fields() {
        assert!(
            parse_envelope(
                r#"{"type":"events_api","payload":{"event":
               {"type":"message","channel":"C1","user":"U1","text":"hi"}}}"#
            )
            .is_err()
        );
        assert!(
            parse_envelope(
                r#"{"envelope_id":"x","type":"events_api","payload":{"event":
               {"type":"message","channel":"C1","text":"hi"}}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn response_contract() {
        #[derive(serde::Deserialize, PartialEq, Debug)]
        struct Payload {
            value: String,
        }
        let parsed: SlackResponse<Payload> = serde_json::from_value(serde_json::json!({
            "ok": true,
            "value": "present"
        }))
        .expect("success response");
        assert_eq!(
            parsed.into_result(),
            Ok(Payload {
                value: "present".into()
            })
        );
        let parsed: SlackResponse<Payload> = serde_json::from_value(serde_json::json!({
            "ok": false,
            "error": "not_authed"
        }))
        .expect("failure response");
        assert_eq!(parsed.into_result(), Err("not_authed".to_string()));
    }

    #[test]
    fn renders_and_routes() {
        assert_eq!(
            crate::bouncer::render_bridged_privmsg("slack", "U1", "#general", "hi"),
            vec![":U1!U1@slack PRIVMSG #general :hi"]
        );
        let mut map = HashMap::new();
        map.insert("#general".to_string(), "C1".to_string());
        use crate::bouncer::{RouteResult, route_privmsg};
        assert_eq!(
            route_privmsg("PRIVMSG #general :hello", &map),
            vec![RouteResult::Deliver("C1".to_string(), "hello".to_string())]
        );
        // Case-insensitive routing.
        assert_eq!(
            route_privmsg("PRIVMSG #GENERAL :hi", &map),
            vec![RouteResult::Deliver("C1".to_string(), "hi".to_string())]
        );
        // A PRIVMSG to a non-bridged channel is surfaced, not silently dropped.
        assert_eq!(
            route_privmsg("PRIVMSG #nope :x", &map),
            vec![RouteResult::Unmapped("#nope".to_string())]
        );
    }

    #[test]
    fn api_base_default_and_override() {
        let mut c = SlackConfig {
            bot_token: "b".into(),
            app_token: "a".into(),
            api_base: String::new(),
            channels: vec![],
            buffer_cap: 10,
        };
        assert_eq!(
            crate::bouncer::bridge_api_base(&c.api_base, DEFAULT_API),
            DEFAULT_API
        );
        c.api_base = "http://localhost:9/".into();
        assert_eq!(
            crate::bouncer::bridge_api_base(&c.api_base, DEFAULT_API),
            "http://localhost:9"
        );
    }

    #[tokio::test]
    #[cfg(feature = "discord")]
    async fn real_http_and_websocket_transport_bridge_both_directions() {
        use crate::bouncer::NetworkHandle;
        use crate::bouncer::bridge_oracle::Provider;

        let mut oracle = crate::bouncer::bridge_oracle::start(Provider::Slack).await;
        let config = SlackConfig {
            bot_token: "xoxb-token".into(),
            app_token: "xapp-token".into(),
            api_base: oracle.api_base.clone(),
            channels: vec!["C1".into()],
            buffer_cap: 10,
        };
        let (handle, mut ends) = NetworkHandle::channels(10);
        let driver_events = handle.subscribe();
        let session = tokio::spawn(async move { session_once(&config, &mut ends).await });

        crate::bouncer::bridge_oracle::verify_round_trip(
            Provider::Slack,
            handle,
            driver_events,
            session,
            &mut oracle,
        )
        .await;
    }
}
