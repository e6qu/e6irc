//! The `slack` bridge driver (DESIGN §10.5): a [`NetworkDriver`] that
//! presents a Slack workspace as a BNC network over Socket Mode. It opens
//! a Socket Mode WebSocket with the app-level token, ACKs event envelopes,
//! and bridges channel `message` events to IRC PRIVMSG lines; the reverse
//! direction posts via the Web API `chat.postMessage` with the bot token.
//! All HTTP/WebSocket code lives behind the `slack` feature.
//!
//! Mapping: each configured channel id is looked up once for its name and
//! bridged as IRC channel `#name`; a message's `user` ⇄ nick; `text` ⇄
//! PRIVMSG text. Bot messages (which carry `bot_id`) are dropped so the
//! bridge does not echo its own posts into a loop.
//!
//! There is no self-hostable Slack server. CI therefore drives the complete
//! HTTP/WebSocket transport against a strict in-process protocol oracle
//! (authorization, channel/user lookup, Socket Mode open/event/ACK, inbound
//! mapping, and outbound Web API), while live provider qualification remains
//! credential-gated.

use super::BoundedJson;
use std::collections::HashMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
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

    fn start(self: Box<Self>) -> NetworkHandle {
        let (handle, ends) = NetworkHandle::channels(self.config.buffer_cap);
        tokio::spawn(run(self.config, ends));
        handle
    }
}

fn api_base(config: &SlackConfig) -> String {
    if config.api_base.is_empty() {
        DEFAULT_API.to_string()
    } else {
        config.api_base.trim_end_matches('/').to_string()
    }
}

async fn run(config: SlackConfig, mut ends: DriverEnds) {
    // Always-on: reconnect (from scratch) with backoff on any socket drop —
    // including Slack's routine `disconnect` envelope, which expects a
    // reconnect — rather than dying and silently dropping all later messages.
    // Only a dropped handle stops the driver.
    super::run_with_backoff(config, &mut ends, |config, ends| {
        Box::pin(session_once(config, ends))
    })
    .await;
}

async fn session_once(config: &SlackConfig, ends: &mut DriverEnds) -> super::SessionOutcome {
    use super::NetworkFailure;
    use super::SessionOutcome::Dropped;
    // Bound REST calls so a hung request can't stall the socket loop; vet every
    // resolved IP and refuse redirects (SSRF control; see `bridge_http_client`).
    let http = match super::bridge_http_client(Duration::from_secs(30)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("slack: http client build failed: {e}");
            return Dropped(NetworkFailure::UpstreamRequestFailed);
        }
    };
    let base = api_base(config);

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
    // Bound the WS handshake so a black-holed socket can't wedge the driver.
    let ws = match tokio::time::timeout(
        Duration::from_secs(30),
        super::bridge_ws_connect(&ws_url, super::bridge_ws_config()),
    )
    .await
    {
        Ok(Ok(ws)) => ws,
        Ok(Err(e)) => {
            eprintln!("slack: socket connect failed: {e}");
            return Dropped(NetworkFailure::ConnectionFailed);
        }
        Err(_) => {
            eprintln!("slack: socket connect timed out");
            return Dropped(NetworkFailure::ConnectionTimedOut);
        }
    };
    let (mut write, mut read) = ws.split();
    ends.emit(ConnectionEvent::Connected);

    // User-id → display-name cache, populated lazily via users.info.
    let mut user_names: HashMap<String, String> = HashMap::new();

    // Slack sends pings and disconnect envelopes regularly; no data for well
    // over a minute means the socket is black-holed — reconnect, don't hang.
    let read_timeout = Duration::from_secs(90);
    loop {
        tokio::select! {
            frame = tokio::time::timeout(read_timeout, read.next()) => {
                let Ok(frame) = frame else {
                    eprintln!("slack: socket idle past timeout; reconnecting");
                    return Dropped(NetworkFailure::KeepaliveTimedOut);
                };
                let text = match frame {
                    Some(Ok(Ws::Text(t))) => t.as_str().to_string(),
                    Some(Ok(Ws::Ping(p))) => {
                        if write.send(Ws::Pong(p)).await.is_err() {
                            return Dropped(NetworkFailure::UpstreamWriteFailed);
                        }
                        continue;
                    }
                    Some(Ok(Ws::Close(_))) | None => {
                        return Dropped(NetworkFailure::ConnectionLost);
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => {
                        eprintln!("slack: socket read error: {e}");
                        return Dropped(NetworkFailure::ConnectionLost);
                    }
                };
                let envelope = match parse_envelope(&text) {
                    Ok(envelope) => envelope,
                    Err(e) => {
                        eprintln!("slack: malformed Socket Mode frame: {e}");
                        return Dropped(NetworkFailure::UpstreamProtocolFailed);
                    }
                };
                // Socket Mode requires acknowledging each envelope by id.
                if let Some(ack_id) = &envelope.ack {
                    let ack = serde_json::json!({ "envelope_id": ack_id });
                    if write.send(Ws::text(ack.to_string())).await.is_err() {
                        return Dropped(NetworkFailure::UpstreamWriteFailed);
                    }
                }
                if envelope.disconnect {
                    return Dropped(NetworkFailure::ConnectionLost);
                }
                if let Some(m) = envelope.message
                    && let Some(channel) = id_to_channel.get(&m.channel).cloned()
                {
                    // Resolve the opaque user id to a display name once, cached;
                    // fall back to the raw id if the lookup fails (better an ugly
                    // nick than a dropped message).
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
                // One line may resolve to several targets (a comma list).
                Some(line) => {
                    // One line may resolve to several targets (a comma list); each
                    // target's outcome is surfaced independently by `relay_routed`.
                    let routed = super::route_privmsg(&line, &channel_to_id);
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

/// One bridged Slack message.
struct SlackMessage {
    channel: String,
    user: String,
    text: String,
}

/// A parsed Socket Mode frame: the envelope id to acknowledge (if any),
/// whether Slack asked us to disconnect, and any user message it carried.
/// Pure, so it is unit-tested with synthetic frames.
struct Envelope {
    ack: Option<String>,
    disconnect: bool,
    message: Option<SlackMessage>,
}

#[derive(serde::Deserialize)]
struct SocketFrame {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    envelope_id: Option<String>,
    #[serde(default)]
    payload: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct SocketPayload {
    event: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct SlackEvent {
    #[serde(rename = "type")]
    kind: String,
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

fn parse_envelope(text: &str) -> Result<Envelope, String> {
    let frame: SocketFrame =
        serde_json::from_str(text).map_err(|e| format!("Socket Mode JSON: {e}"))?;
    if frame.kind == "disconnect" {
        return Ok(Envelope {
            ack: frame.envelope_id,
            disconnect: true,
            message: None,
        });
    }
    if frame.kind != "events_api" {
        return Ok(Envelope {
            ack: frame.envelope_id,
            disconnect: false,
            message: None,
        });
    }

    let ack = frame
        .envelope_id
        .ok_or("events_api frame had no envelope_id")?;
    let payload: SocketPayload =
        serde_json::from_value(frame.payload.ok_or("events_api frame had no payload")?)
            .map_err(|e| format!("events_api payload: {e}"))?;
    let event: SlackEvent =
        serde_json::from_value(payload.event).map_err(|e| format!("events_api event: {e}"))?;
    // A real user message: inner event type "message", no bot_id (drop our
    // own and other bots' posts), and no subtype (edits/joins/etc. carry one).
    let message = if event.kind == "message" && event.bot_id.is_none() && event.subtype.is_none() {
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

/// A Slack Web API response's `ok` field is the error contract: `false`
/// carries an `error` string.
fn check_ok(v: &serde_json::Value) -> Result<(), String> {
    if v["ok"].as_bool() == Some(true) {
        Ok(())
    } else {
        Err(v["error"].as_str().unwrap_or("slack api error").to_string())
    }
}

/// Turn a Slack REST failure into a session outcome. Slack signals auth failures
/// with HTTP 200 + `ok:false` and an `error` naming a bad/revoked/expired token;
/// those are permanent, so stop re-dialing (like the IRC driver on a rejected
/// password) rather than reconnecting forever. Anything else is transient.
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
    let v: serde_json::Value = http
        .post(format!("{base}/apps.connections.open"))
        .header("Authorization", format!("Bearer {app_token}"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .bounded_json()
        .await?;
    check_ok(&v)?;
    v["url"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "apps.connections.open had no url".to_string())
}

async fn fetch_channel_name(
    http: &reqwest::Client,
    base: &str,
    bot_token: &str,
    id: &str,
) -> Result<String, String> {
    let v: serde_json::Value = http
        .get(format!("{base}/conversations.info"))
        .header("Authorization", format!("Bearer {bot_token}"))
        .query(&[("channel", id)])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .bounded_json()
        .await?;
    check_ok(&v)?;
    v["channel"]["name"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("conversations.info for {id} had no name"))
}

/// Resolve a Slack user id (`U12345678`) to a human display name via
/// `users.info`. The `message` event carries only the opaque id, so without
/// this every Slack message on IRC would come from a nick like `U12345678`
/// instead of the sender's actual name. Prefers the display name, then the
/// real name, then the handle.
async fn fetch_user_name(
    http: &reqwest::Client,
    base: &str,
    bot_token: &str,
    id: &str,
) -> Result<String, String> {
    let v: serde_json::Value = http
        .get(format!("{base}/users.info"))
        .header("Authorization", format!("Bearer {bot_token}"))
        .query(&[("user", id)])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .bounded_json()
        .await?;
    check_ok(&v)?;
    let u = &v["user"];
    ["profile.display_name", "profile.real_name"]
        .iter()
        .filter_map(|path| {
            let (a, b) = path.split_once('.').unwrap();
            u[a][b].as_str().filter(|s| !s.is_empty())
        })
        .next()
        .or_else(|| u["name"].as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("users.info for {id} had no name"))
}

async fn post_message(
    http: &reqwest::Client,
    base: &str,
    bot_token: &str,
    channel_id: &str,
    text: &str,
) -> Result<(), String> {
    let req = http
        .post(format!("{base}/chat.postMessage"))
        .header("Authorization", format!("Bearer {bot_token}"))
        .json(&serde_json::json!({ "channel": channel_id, "text": text }));
    // Checked send catches a transport error or non-2xx (e.g. a 429/5xx whose
    // body isn't the usual JSON); `check_ok` then catches Slack's in-body
    // `ok:false` on an otherwise-200 response.
    let v: serde_json::Value = super::bridge_send(req).await?.bounded_json().await?;
    check_ok(&v)
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
    fn ok_contract() {
        assert!(check_ok(&serde_json::json!({ "ok": true })).is_ok());
        assert_eq!(
            check_ok(&serde_json::json!({ "ok": false, "error": "not_authed" })),
            Err("not_authed".to_string())
        );
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
        assert_eq!(api_base(&c), DEFAULT_API);
        c.api_base = "http://localhost:9/".into();
        assert_eq!(api_base(&c), "http://localhost:9");
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
