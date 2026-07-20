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
//! There is no self-hostable Slack server to test against, so the pure
//! mapping/parse/route logic is unit-tested offline and the end-to-end
//! path is covered by a live-gated integration test needing real workspace
//! tokens. This module is NOT verified against live Slack in CI.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as Ws;

use super::{DriverEnds, DriverEvent, NetworkDriver, NetworkHandle};

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
    let mut backoff = Duration::from_millis(200);
    loop {
        let started = tokio::time::Instant::now();
        match session_once(&config, &mut ends).await {
            super::SessionOutcome::Stopped => return,
            super::SessionOutcome::Dropped => {
                ends.emit(DriverEvent::Disconnected);
                // A session that lasted a while clearly connected; reset the
                // backoff so a flapping-but-reachable upstream reconnects
                // promptly instead of escalating toward the 30s cap forever.
                if started.elapsed() >= Duration::from_secs(10) {
                    backoff = Duration::from_millis(200);
                }
                let jitter = Duration::from_millis((backoff.as_millis() as u64) % 97);
                tokio::time::sleep(backoff + jitter).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

async fn session_once(config: &SlackConfig, ends: &mut DriverEnds) -> super::SessionOutcome {
    use super::SessionOutcome::Dropped;
    // Bound REST calls so a hung request can't stall the socket loop.
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("slack: http client build failed: {e}");
            return Dropped;
        }
    };
    let base = api_base(config);

    // Resolve each configured channel id to its #name once.
    let mut id_to_channel: HashMap<String, String> = HashMap::new();
    let mut channel_to_id: HashMap<String, String> = HashMap::new();
    for id in &config.channels {
        match fetch_channel_name(&http, &base, &config.bot_token, id).await {
            Ok(name) => {
                let channel = format!("#{name}");
                id_to_channel.insert(id.clone(), channel.clone());
                channel_to_id.insert(channel, id.clone());
            }
            Err(e) => {
                eprintln!("slack: channel {id} lookup failed: {e}");
                return Dropped;
            }
        }
    }

    let ws_url = match open_socket(&http, &base, &config.app_token).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("slack: apps.connections.open failed: {e}");
            return Dropped;
        }
    };
    let (ws, _) = match tokio_tungstenite::connect_async(&ws_url).await {
        Ok(x) => x,
        Err(e) => {
            eprintln!("slack: socket connect failed: {e}");
            return Dropped;
        }
    };
    let (mut write, mut read) = ws.split();
    ends.emit(DriverEvent::Connected);

    loop {
        tokio::select! {
            frame = read.next() => {
                let text = match frame {
                    Some(Ok(Ws::Text(t))) => t.as_str().to_string(),
                    Some(Ok(Ws::Ping(p))) => {
                        let _ = write.send(Ws::Pong(p)).await;
                        continue;
                    }
                    Some(Ok(Ws::Close(_))) | None => return Dropped,
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => {
                        eprintln!("slack: socket read error: {e}");
                        return Dropped;
                    }
                };
                let envelope = parse_envelope(&text);
                // Socket Mode requires acknowledging each envelope by id.
                if let Some(ack_id) = &envelope.ack {
                    let ack = serde_json::json!({ "envelope_id": ack_id });
                    if write.send(Ws::text(ack.to_string())).await.is_err() {
                        return Dropped;
                    }
                }
                if envelope.disconnect {
                    return Dropped; // Slack asked us to reconnect.
                }
                if let Some(m) = envelope.message
                    && let Some(channel) = id_to_channel.get(&m.channel)
                {
                    ends.emit_line(render_privmsg(&m.user, channel, &m.text));
                }
            }
            cmd = ends.next_command() => match cmd {
                Some(line) => match route_command(&line, &channel_to_id) {
                    super::RouteResult::Deliver(id, text) => {
                        if let Err(e) =
                            post_message(&http, &base, &config.bot_token, &id, &text).await
                        {
                            eprintln!("slack: chat.postMessage to {id} failed: {e}");
                        }
                    }
                    super::RouteResult::Unmapped(target) => {
                        ends.emit_line(format!(
                            ":*bnc* NOTICE {target} :not delivered: no bridged Slack channel for {target}"
                        ));
                    }
                    super::RouteResult::Ignore => {}
                },
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

fn parse_envelope(text: &str) -> Envelope {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Envelope {
            ack: None,
            disconnect: false,
            message: None,
        };
    };
    let ack = v["envelope_id"].as_str().map(str::to_string);
    let kind = v["type"].as_str().unwrap_or("");
    if kind == "disconnect" {
        return Envelope {
            ack,
            disconnect: true,
            message: None,
        };
    }
    // A real user message: type events_api, inner event type "message",
    // no bot_id (drop our own and other bots' posts) and no subtype
    // (edits/joins/etc. carry a subtype we do not bridge).
    let event = &v["payload"]["event"];
    let message = if kind == "events_api"
        && event["type"] == "message"
        && event["bot_id"].is_null()
        && event["subtype"].is_null()
    {
        Some(SlackMessage {
            channel: event["channel"].as_str().unwrap_or("").to_string(),
            user: event["user"].as_str().unwrap_or("?").to_string(),
            text: event["text"].as_str().unwrap_or("").to_string(),
        })
    } else {
        None
    };
    Envelope {
        ack,
        disconnect: false,
        message,
    }
}

/// Render a Slack message as an IRC PRIVMSG line.
fn render_privmsg(user: &str, channel: &str, text: &str) -> String {
    format!(":{user}!{user}@slack PRIVMSG {channel} :{text}")
}

/// A downstream IRC line → (channel id, text) if it is a PRIVMSG to a
/// bridged channel; else `None`.
fn route_command(line: &str, channel_to_id: &HashMap<String, String>) -> super::RouteResult {
    use super::RouteResult;
    let Ok(msg) = e6irc_proto::message::Message::parse(line) else {
        return RouteResult::Ignore;
    };
    if !msg.command.eq_ignore_ascii_case("PRIVMSG") {
        return RouteResult::Ignore;
    }
    let (Some(target), Some(text)) = (msg.params.first(), msg.params.get(1)) else {
        return RouteResult::Ignore;
    };
    match channel_to_id.get(*target) {
        Some(id) => RouteResult::Deliver(id.clone(), text.to_string()),
        None => RouteResult::Unmapped(target.to_string()),
    }
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
        .json()
        .await
        .map_err(|e| e.to_string())?;
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
        .json()
        .await
        .map_err(|e| e.to_string())?;
    check_ok(&v)?;
    v["channel"]["name"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("conversations.info for {id} had no name"))
}

async fn post_message(
    http: &reqwest::Client,
    base: &str,
    bot_token: &str,
    channel_id: &str,
    text: &str,
) -> Result<(), String> {
    let v: serde_json::Value = http
        .post(format!("{base}/chat.postMessage"))
        .header("Authorization", format!("Bearer {bot_token}"))
        .json(&serde_json::json!({ "channel": channel_id, "text": text }))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
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
        );
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
        );
        assert_eq!(e.ack.as_deref(), Some("x")); // still ack it
        assert!(e.message.is_none());
        // Edits/joins carry a subtype.
        let e = parse_envelope(
            r#"{"envelope_id":"y","type":"events_api","payload":{"event":
               {"type":"message","subtype":"channel_join","channel":"C1","user":"U1"}}}"#,
        );
        assert!(e.message.is_none());
    }

    #[test]
    fn handles_disconnect_and_garbage() {
        let e = parse_envelope(r#"{"type":"disconnect","reason":"refresh"}"#);
        assert!(e.disconnect);
        let e = parse_envelope("not json");
        assert!(e.ack.is_none() && !e.disconnect && e.message.is_none());
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
            render_privmsg("U1", "#general", "hi"),
            ":U1!U1@slack PRIVMSG #general :hi"
        );
        let mut map = HashMap::new();
        map.insert("#general".to_string(), "C1".to_string());
        use crate::bouncer::RouteResult;
        assert_eq!(
            route_command("PRIVMSG #general :hello", &map),
            RouteResult::Deliver("C1".to_string(), "hello".to_string())
        );
        // A PRIVMSG to a non-bridged channel is surfaced, not silently dropped.
        assert_eq!(
            route_command("PRIVMSG #nope :x", &map),
            RouteResult::Unmapped("#nope".to_string())
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
}
